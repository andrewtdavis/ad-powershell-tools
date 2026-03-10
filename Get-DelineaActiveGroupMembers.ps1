<#
.INFO
  Synopsis:
    Enumerate active AD group members across domains and enrich them with Delinea zone attributes.

  Description:
    Resolves an Active Directory group, expands nested group membership recursively across
    domains, filters to active AD users by default, and optionally enriches the output
    with Delinea user profile attributes from a specified Delinea zone.

    Delinea behavior:
      - Delinea cmdlets are only called when a Delinea-backed output field is requested
      - The Delinea zone is resolved once
      - The script attempts a one-time zone preload into a local hashtable
      - If zone preload is not supported by the installed Delinea module, the script
        falls back to targeted per-user lookups
      - Positive and negative Delinea lookup results are cached for the duration of the run
      - If a user is present in the AD group but missing in Delinea, the script flags
        that as a provisioning gap

    AD behavior:
      - Nested groups are expanded recursively
      - Cross-domain member resolution is supported
      - Disabled users are excluded by default
      - Expired users are excluded by default
      - Use -IncludeDisabled and/or -IncludeExpired to override

    Output:
      - Default output is PowerShell objects
      - -Csv outputs CSV text
      - -Tsv outputs TSV text

  Parameters:
    -GroupName
      Group name, sAMAccountName, CN, SID, or distinguished name.

    -Domains
      One or more domains or domain controllers to query.
      The singular alias -Domain is also supported.

    -CdmZone
      Delinea zone name, canonical path, or distinguished name.
      Required only when a Delinea-backed field is requested.

    -CascadeZoneLookup
      If set, Delinea profile lookup walks parent zones when a profile is not found
      in the requested zone.

    -Fields
      Explicit output columns.

    -Name
      Include Name in legacy output mode.

    -Email
      Include Email in legacy output mode.

    -Attributes
      Additional attributes in legacy output mode.

    -IncludeDisabled
      Include disabled users.

    -IncludeExpired
      Include expired users.

    -Csv
      Output as CSV.

    -Tsv
      Output as TSV.

  Examples:
    .\Get-DelineaActiveGroupMembers.ps1 "Example_Group" `
      -Domain "example.corp.local" `
      -Fields SamAccountName,Email

    .\Get-DelineaActiveGroupMembers.ps1 "Example_Group" `
      -Domain "example.corp.local" `
      -Fields SamAccountName,Email,UnixUid,DelineaStatus,MissingDelineaAttributes `
      -CdmZone "Global Zone/Engineering"

    .\Get-DelineaActiveGroupMembers.ps1 "Example_Group" `
      -Domains "example.corp.local","child.example.corp.local" `
      -Fields SamAccountName,Name,Email,DelineaZone,UnixLogin,UnixUid,PrimaryGroupId `
      -CdmZone "Engineering" `
      -CascadeZoneLookup `
      -Tsv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Alias('Group')]
    [string]$GroupName,

    [Parameter(Mandatory = $false)]
    [Alias('Domain')]
    [string[]]$Domains = @(),

    [Parameter(Mandatory = $false)]
    [string]$CdmZone,

    [Parameter(Mandatory = $false)]
    [switch]$CascadeZoneLookup,

    [Parameter(Mandatory = $false)]
    [string[]]$Fields = @(),

    [Parameter(Mandatory = $false)]
    [switch]$Name,

    [Parameter(Mandatory = $false)]
    [switch]$Email,

    [Parameter(Mandatory = $false)]
    [string[]]$Attributes = @(),

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabled,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeExpired,

    [Parameter(Mandatory = $false)]
    [switch]$Csv,

    [Parameter(Mandatory = $false)]
    [switch]$Tsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Csv -and $Tsv) {
    throw "Parameters -Csv and -Tsv are mutually exclusive."
}

Import-Module ActiveDirectory -ErrorAction Stop

# Delinea module is imported only if Delinea-backed fields are requested

$script:DelineaProfileCache = @{}
$script:DelineaNegativeSentinel = [pscustomobject]@{ __NotFound = $true }
$script:DelineaZoneIndex = @{}
$script:DelineaZonePreloadComplete = @{}

function Get-ParentDn {
    param(
        [AllowNull()]
        [string]$DistinguishedName
    )

    if (-not $DistinguishedName) { return $null }

    $parts = $DistinguishedName -split ',', 2
    if ($parts.Count -lt 2) { return $null }

    return $parts[1]
}

function Get-DomainFromDistinguishedName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName
    )

    $dcParts = @()
    foreach ($part in ($DistinguishedName -split ',')) {
        $p = $part.Trim()
        if ($p -match '^(?i)DC=(.+)$') {
            $dcParts += $Matches[1]
        }
    }

    if (@($dcParts).Count -gt 0) {
        return ($dcParts -join '.')
    }

    return $null
}

function Get-FallbackDomainList {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object]$ExplicitDomains
    )

    $explicitList = @()
    if ($null -ne $ExplicitDomains) {
        $explicitList = @($ExplicitDomains) |
            Where-Object { $_ -and ([string]$_).Trim().Length -gt 0 } |
            ForEach-Object { ([string]$_).Trim() } |
            Select-Object -Unique
    }

    if (@($explicitList).Count -gt 0) {
        return [string[]]$explicitList
    }

    try {
        $forest = Get-ADForest -ErrorAction Stop
        if ($forest -and $forest.Domains -and @($forest.Domains).Count -gt 0) {
            return [string[]]@($forest.Domains)
        }
    } catch {
        # Best-effort only
    }

    return @()
}

function Resolve-ADGroupCrossDomain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [object]$DomainList
    )

    $dl = @()
    if ($null -ne $DomainList) { $dl = @($DomainList) }

    if (@($dl).Count -eq 0) {
        return Get-ADGroup -Identity $Identity -ErrorAction Stop
    }

    foreach ($d in $dl) {
        if (-not $d) { continue }
        $ds = ([string]$d).Trim()
        if (-not $ds) { continue }

        try {
            return Get-ADGroup -Server $ds -Identity $Identity -ErrorAction Stop
        } catch {
            continue
        }
    }

    return $null
}

function Get-ADGroupMembersCrossDomain {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.ActiveDirectory.Management.ADGroup]$Group,

        [Parameter(Mandatory = $true)]
        [object]$DomainList
    )

    $groupDomain = $null
    if ($Group.DistinguishedName) {
        $groupDomain = Get-DomainFromDistinguishedName -DistinguishedName $Group.DistinguishedName
    }

    $dl = @()
    if ($null -ne $DomainList) { $dl = @($DomainList) }

    $tryList = New-Object System.Collections.Generic.List[string]
    if ($groupDomain) { [void]$tryList.Add($groupDomain) }

    foreach ($d in $dl) {
        if (-not $d) { continue }
        $ds = ([string]$d).Trim()
        if (-not $ds) { continue }
        if (-not $tryList.Contains($ds)) { [void]$tryList.Add($ds) }
    }

    if ($tryList.Count -eq 0) {
        return Get-ADGroupMember -Identity $Group.DistinguishedName -Recursive -ErrorAction Stop
    }

    foreach ($d in $tryList) {
        try {
            return Get-ADGroupMember -Server $d -Identity $Group.DistinguishedName -Recursive -ErrorAction Stop
        } catch {
            continue
        }
    }

    throw "Failed to enumerate members for group '$($Group.Name)'."
}

function Get-ADUserCrossDomain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,

        [Parameter(Mandatory = $true)]
        [string[]]$Properties,

        [Parameter(Mandatory = $true)]
        [object]$FallbackDomains
    )

    $tryList = New-Object System.Collections.Generic.List[string]

    $dnDomain = Get-DomainFromDistinguishedName -DistinguishedName $DistinguishedName
    if ($dnDomain) { [void]$tryList.Add($dnDomain) }

    $fallbackList = @()
    if ($null -ne $FallbackDomains) { $fallbackList = @($FallbackDomains) }

    foreach ($d in $fallbackList) {
        if (-not $d) { continue }
        $ds = ([string]$d).Trim()
        if (-not $ds) { continue }
        if (-not $tryList.Contains($ds)) { [void]$tryList.Add($ds) }
    }

    if ($tryList.Count -eq 0) {
        try { return Get-ADUser -Identity $DistinguishedName -Properties $Properties }
        catch { return $null }
    }

    foreach ($tryDomain in $tryList) {
        try {
            return Get-ADUser -Server $tryDomain -Identity $DistinguishedName -Properties $Properties
        } catch {
            continue
        }
    }

    return $null
}

function Normalize-UniqueNonEmpty {
    param([string[]]$Values)

    if (-not $Values) { return @() }

    return @(
        $Values |
        Where-Object { $_ -and $_.Trim().Length -gt 0 } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique
    )
}

function Convert-ADValueToDisplayString {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [byte[]]) {
        return ("BINARY ({0} bytes)" -f $Value.Length)
    }

    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
        $items = @()
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            if ($item -is [byte[]]) {
                $items += ("BINARY ({0} bytes)" -f $item.Length)
            } else {
                $items += [string]$item
            }
        }
        return ($items -join '; ')
    }

    return [string]$Value
}

function Convert-DelineaValueToDisplayString {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }

    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
        $items = @()
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            $items += [string]$item
        }
        return ($items -join '; ')
    }

    return [string]$Value
}

function ConvertTo-Tsv {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]$Properties
    )

    $escape = {
        param([object]$v)
        if ($null -eq $v) { return '' }
        $s = [string]$v
        if ($s -match '[\t\r\n"]') {
            return '"' + ($s -replace '"', '""') + '"'
        }
        return $s
    }

    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add(($Properties -join "`t"))

    foreach ($row in $InputObject) {
        $fields = foreach ($p in $Properties) {
            & $escape ($row.$p)
        }
        [void]$lines.Add(($fields -join "`t"))
    }

    return ($lines -join "`r`n")
}

function Test-UserIsActive {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$UserObject,

        [switch]$IncludeDisabled,
        [switch]$IncludeExpired
    )

    if (-not $IncludeDisabled) {
        if ($UserObject.PSObject.Properties.Match('Enabled').Count -gt 0) {
            if ($UserObject.Enabled -eq $false) { return $false }
        }
    }

    if (-not $IncludeExpired) {
        if ($UserObject.PSObject.Properties.Match('AccountExpirationDate').Count -gt 0) {
            $aed = $UserObject.AccountExpirationDate
            if ($aed -is [DateTime]) {
                if ($aed -lt (Get-Date)) { return $false }
            }
        }
    }

    return $true
}

function Build-FieldPlan {
    param(
        [string[]]$ExplicitFields,
        [switch]$LegacyName,
        [switch]$LegacyEmail,
        [string[]]$LegacyAttributes
    )

    $columnToAdProp = [ordered]@{}
    $outColumns = New-Object System.Collections.Generic.List[string]
    $adProps = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    $addColumn = {
        param([string]$ColumnName, [AllowNull()][string]$AdPropName)

        if (-not $columnToAdProp.Contains($ColumnName)) {
            $columnToAdProp[$ColumnName] = $AdPropName
            [void]$outColumns.Add($ColumnName)
        }

        if ($AdPropName -and $AdPropName.Trim()) {
            [void]$adProps.Add($AdPropName)
        }
    }

    $explicit = Normalize-UniqueNonEmpty -Values $ExplicitFields

    if (@($explicit).Count -gt 0) {
        foreach ($f in $explicit) {
            switch -Regex ($f) {
                '^(?i)samaccountname$'                 { & $addColumn 'SamAccountName' 'SamAccountName' }
                '^(?i)name$'                           { & $addColumn 'Name' 'Name' }
                '^(?i)(email|mail)$'                   { & $addColumn 'Email' 'mail' }
                '^(?i)(OU|OrganizationalUnit)$'        { & $addColumn 'OU' 'DistinguishedName' }
                '^(?i)DelineaZone$'                    { & $addColumn 'DelineaZone' $null }
                '^(?i)UnixLogin$'                      { & $addColumn 'UnixLogin' $null }
                '^(?i)(UnixUid|UidNumber)$'            { & $addColumn 'UnixUid' $null }
                '^(?i)PrimaryGroupId$'                 { & $addColumn 'PrimaryGroupId' $null }
                '^(?i)DelineaStatus$'                  { & $addColumn 'DelineaStatus' $null }
                '^(?i)MissingDelineaAttributes$'       { & $addColumn 'MissingDelineaAttributes' $null }
                default                                { & $addColumn $f $f }
            }
        }

        if (-not $columnToAdProp.Contains('SamAccountName')) {
            $existing = @($outColumns)
            $outColumns.Clear()
            & $addColumn 'SamAccountName' 'SamAccountName' | Out-Null
            foreach ($c in $existing) {
                if ($c -ne 'SamAccountName') { [void]$outColumns.Add($c) }
            }
        }

        return [pscustomobject]@{
            OutColumns     = [string[]]$outColumns
            AdProps        = [string[]]$adProps
            ColumnToAdProp = $columnToAdProp
            UsesExplicit   = $true
        }
    }

    & $addColumn 'SamAccountName' 'SamAccountName' | Out-Null
    if ($LegacyName)  { & $addColumn 'Name' 'Name' | Out-Null }
    if ($LegacyEmail) { & $addColumn 'Email' 'mail' | Out-Null }

    $extras = Normalize-UniqueNonEmpty -Values $LegacyAttributes |
        Where-Object { $_ -notin @('SamAccountName', 'Name', 'Email', 'mail') }

    foreach ($p in $extras) {
        switch -Regex ($p) {
            '^(?i)(OU|OrganizationalUnit)$'        { & $addColumn 'OU' 'DistinguishedName' | Out-Null }
            '^(?i)DelineaZone$'                    { & $addColumn 'DelineaZone' $null | Out-Null }
            '^(?i)UnixLogin$'                      { & $addColumn 'UnixLogin' $null | Out-Null }
            '^(?i)(UnixUid|UidNumber)$'            { & $addColumn 'UnixUid' $null | Out-Null }
            '^(?i)PrimaryGroupId$'                 { & $addColumn 'PrimaryGroupId' $null | Out-Null }
            '^(?i)DelineaStatus$'                  { & $addColumn 'DelineaStatus' $null | Out-Null }
            '^(?i)MissingDelineaAttributes$'       { & $addColumn 'MissingDelineaAttributes' $null | Out-Null }
            default                                { & $addColumn $p $p | Out-Null }
        }
    }

    return [pscustomobject]@{
        OutColumns     = [string[]]$outColumns
        AdProps        = [string[]]$adProps
        ColumnToAdProp = $columnToAdProp
        UsesExplicit   = $false
    }
}

function Test-NeedsDelineaLookup {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Columns
    )

    foreach ($c in @($Columns)) {
        if ($c -match '^(?i)(DelineaZone|UnixLogin|UnixUid|UidNumber|PrimaryGroupId|DelineaStatus|MissingDelineaAttributes)$') {
            return $true
        }
    }

    return $false
}

function Initialize-DelineaCaches {
    $script:DelineaProfileCache = @{}
    $script:DelineaZoneIndex = @{}
    $script:DelineaZonePreloadComplete = @{}
}

function Get-DelineaZoneKey {
    param(
        [Parameter(Mandatory = $true)]
        $Zone
    )

    if ($Zone -is [string]) { return $Zone }

    if ($Zone.PSObject.Properties.Match('DistinguishedName').Count -gt 0 -and $Zone.DistinguishedName) {
        return [string]$Zone.DistinguishedName
    }

    if ($Zone.PSObject.Properties.Match('CanonicalName').Count -gt 0 -and $Zone.CanonicalName) {
        return [string]$Zone.CanonicalName
    }

    if ($Zone.PSObject.Properties.Match('Name').Count -gt 0 -and $Zone.Name) {
        return [string]$Zone.Name
    }

    return [string]$Zone
}

function Resolve-CdmZoneObject {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZoneInput
    )

    $allZones = @(Get-CdmZone -ErrorAction Stop)
    if (-not $allZones -or $allZones.Count -eq 0) {
        throw "Get-CdmZone returned no zones."
    }

    $normalizedInput = ($ZoneInput -replace '\\', '/').Trim().Trim('/')

    $byDn = @(
        $allZones | Where-Object {
            $_.DistinguishedName -and $_.DistinguishedName -eq $ZoneInput
        }
    )
    if ($byDn.Count -eq 1) { return $byDn[0] }
    if ($byDn.Count -gt 1) {
        throw "Multiple Delinea zones matched distinguished name '$ZoneInput'."
    }

    $byCanonicalExact = @(
        $allZones | Where-Object {
            $_.CanonicalName -and
            (($_.CanonicalName -replace '\\', '/').Trim().Trim('/')) -eq $normalizedInput
        }
    )
    if ($byCanonicalExact.Count -eq 1) { return $byCanonicalExact[0] }
    if ($byCanonicalExact.Count -gt 1) {
        $matches = ($byCanonicalExact | Select-Object -ExpandProperty CanonicalName) -join ', '
        throw "Multiple Delinea zones matched canonical path '$ZoneInput'. Matches: $matches"
    }

    $byName = @(
        $allZones | Where-Object {
            $_.Name -and $_.Name -eq $ZoneInput
        }
    )
    if ($byName.Count -eq 1) { return $byName[0] }

    $leafName = ($normalizedInput -split '/')[(-1)]
    $byLeaf = @(
        $allZones | Where-Object {
            $_.Name -and $_.Name -eq $leafName
        }
    )
    if ($byLeaf.Count -eq 1) { return $byLeaf[0] }

    $byCanonicalSuffix = @(
        $allZones | Where-Object {
            if (-not $_.CanonicalName) { return $false }

            $canon = (($_.CanonicalName -replace '\\', '/').Trim().Trim('/'))

            if ($canon -eq $normalizedInput) { return $true }
            if ($canon -like "*/$normalizedInput") { return $true }

            return $false
        }
    )

    if ($byCanonicalSuffix.Count -eq 1) {
        return $byCanonicalSuffix[0]
    }

    if ($byCanonicalSuffix.Count -gt 1) {
        $matches = ($byCanonicalSuffix | Select-Object -ExpandProperty CanonicalName) -join ', '
        throw "Multiple Delinea zones matched path suffix '$ZoneInput'. Use a more specific path. Matches: $matches"
    }

    if ($byLeaf.Count -gt 1) {
        $matches = ($byLeaf | Select-Object -ExpandProperty CanonicalName) -join ', '
        throw "Multiple Delinea zones matched leaf name '$leafName'. Use a more specific path. Matches: $matches"
    }

    throw "Failed to resolve Delinea zone '$ZoneInput'."
}

function Build-ZoneLookupMap {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$AllZones
    )

    $map = @{}
    foreach ($z in @($AllZones)) {
        if ($z.DistinguishedName) {
            $map[$z.DistinguishedName] = $z
        }
    }

    return $map
}

function Get-CdmUserProfileSafe {
    param(
        [Parameter(Mandatory = $true)]
        $Zone,

        [Parameter(Mandatory = $true)]
        [string]$UserName
    )

    try {
        $zoneArg = $Zone

        if ($Zone -isnot [string]) {
            if ($Zone.PSObject.Properties.Match('DistinguishedName').Count -gt 0 -and $Zone.DistinguishedName) {
                $zoneArg = [string]$Zone.DistinguishedName
            }
        }

        return Get-CdmUserProfile -Zone $zoneArg -User $UserName -ErrorAction Stop
    } catch {
        return $null
    }
}

function Get-CdmUserProfileCascade {
    param(
        [Parameter(Mandatory = $true)]
        $StartZone,

        [Parameter(Mandatory = $true)]
        [string]$UserName,

        [Parameter(Mandatory = $true)]
        [hashtable]$ZoneByDn
    )

    $current = $StartZone
    $maxDepth = 16
    $depth = 0

    while ($current -and $depth -lt $maxDepth) {
        $profile = Get-CdmUserProfileSafe -Zone $current -UserName $UserName
        if ($profile) { return $profile }

        if ($current.Parent -and $ZoneByDn.ContainsKey($current.Parent)) {
            $current = $ZoneByDn[$current.Parent]
            $depth++
            continue
        }

        break
    }

    return $null
}

function New-DelineaIdentityKeysForAdUser {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$AdUser
    )

    $keys = New-Object System.Collections.Generic.List[string]

    if ($AdUser.SID) {
        [void]$keys.Add(("SID:{0}" -f [string]$AdUser.SID))
    }

    if ($AdUser.UserPrincipalName) {
        [void]$keys.Add(("UPN:{0}" -f [string]$AdUser.UserPrincipalName).ToLowerInvariant())
    }

    if ($AdUser.SamAccountName) {
        [void]$keys.Add(("SAM:{0}" -f [string]$AdUser.SamAccountName).ToLowerInvariant())
    }

    if ($AdUser.DistinguishedName) {
        [void]$keys.Add(("DN:{0}" -f [string]$AdUser.DistinguishedName).ToLowerInvariant())

        $userDomain = Get-DomainFromDistinguishedName -DistinguishedName $AdUser.DistinguishedName
        if ($userDomain -and $AdUser.SamAccountName) {
            [void]$keys.Add(("UPN:{0}" -f ("{0}@{1}" -f $AdUser.SamAccountName, $userDomain)).ToLowerInvariant())
        }

        $cnPart = ([string]$AdUser.DistinguishedName -split ',')[0]
        if ($cnPart -match '^(?i)CN=(.+)$') {
            [void]$keys.Add(("CN:{0}" -f $Matches[1]).ToLowerInvariant())
        }
    }

    return @($keys | Select-Object -Unique)
}

function Get-DelineaCachedProfileByKeys {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZoneKey,

        [Parameter(Mandatory = $true)]
        [string[]]$IdentityKeys
    )

    foreach ($k in @($IdentityKeys)) {
        $fullKey = ("{0}|{1}" -f $ZoneKey.ToLowerInvariant(), $k)
        if ($script:DelineaProfileCache.ContainsKey($fullKey)) {
            return $script:DelineaProfileCache[$fullKey]
        }
    }

    return $null
}

function Set-DelineaCachedProfileByKeys {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZoneKey,

        [Parameter(Mandatory = $true)]
        [string[]]$IdentityKeys,

        [AllowNull()]
        $Profile
    )

    foreach ($k in @($IdentityKeys)) {
        $fullKey = ("{0}|{1}" -f $ZoneKey.ToLowerInvariant(), $k)
        if ($null -eq $Profile) {
            $script:DelineaProfileCache[$fullKey] = $script:DelineaNegativeSentinel
        } else {
            $script:DelineaProfileCache[$fullKey] = $Profile
        }
    }
}

function Add-DelineaProfileToZoneIndex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZoneKey,

        [Parameter(Mandatory = $true)]
        $Profile
    )

    if (-not $script:DelineaZoneIndex.ContainsKey($ZoneKey)) {
        $script:DelineaZoneIndex[$ZoneKey] = @{}
    }

    $index = $script:DelineaZoneIndex[$ZoneKey]
    $keys = New-Object System.Collections.Generic.List[string]

    if ($Profile.PSObject.Properties.Match('Sid').Count -gt 0 -and $Profile.Sid) {
        [void]$keys.Add(("SID:{0}" -f [string]$Profile.Sid))
    }

    if ($Profile.PSObject.Properties.Match('User').Count -gt 0 -and $Profile.User) {
        [void]$keys.Add(("UPN:{0}" -f [string]$Profile.User).ToLowerInvariant())
        [void]$keys.Add(("SAM:{0}" -f [string]$Profile.User).ToLowerInvariant())
    }

    if ($Profile.PSObject.Properties.Match('Name').Count -gt 0 -and $Profile.Name) {
        [void]$keys.Add(("SAM:{0}" -f [string]$Profile.Name).ToLowerInvariant())
        [void]$keys.Add(("CN:{0}" -f [string]$Profile.Name).ToLowerInvariant())
    }

    if ($Profile.PSObject.Properties.Match('DistinguishedName').Count -gt 0 -and $Profile.DistinguishedName) {
        [void]$keys.Add(("DN:{0}" -f [string]$Profile.DistinguishedName).ToLowerInvariant())
    }

    foreach ($k in @($keys | Select-Object -Unique)) {
        $index[$k] = $Profile
    }
}

function Get-DelineaProfileFromZoneIndex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZoneKey,

        [Parameter(Mandatory = $true)]
        [string[]]$IdentityKeys
    )

    if (-not $script:DelineaZoneIndex.ContainsKey($ZoneKey)) {
        return $null
    }

    $index = $script:DelineaZoneIndex[$ZoneKey]
    foreach ($k in @($IdentityKeys)) {
        if ($index.ContainsKey($k)) {
            return $index[$k]
        }
    }

    return $null
}

function Initialize-DelineaZoneIndex {
    param(
        [Parameter(Mandatory = $true)]
        $Zone
    )

    $zoneKey = Get-DelineaZoneKey -Zone $Zone

    if ($script:DelineaZonePreloadComplete.ContainsKey($zoneKey)) {
        return
    }

    $script:DelineaZonePreloadComplete[$zoneKey] = $true

    Write-Verbose ("Attempting Delinea zone preload for '{0}'" -f $zoneKey)

    try {
        $zoneArg = $Zone
        if ($Zone -isnot [string]) {
            if ($Zone.PSObject.Properties.Match('DistinguishedName').Count -gt 0 -and $Zone.DistinguishedName) {
                $zoneArg = [string]$Zone.DistinguishedName
            }
        }

        $profiles = @(Get-CdmUserProfile -Zone $zoneArg -ErrorAction Stop)

        foreach ($p in @($profiles)) {
            Add-DelineaProfileToZoneIndex -ZoneKey $zoneKey -Profile $p
        }

        Write-Verbose ("Preloaded {0} Delinea profiles for zone '{1}'" -f @($profiles).Count, $zoneKey)
    } catch {
        Write-Verbose ("Zone preload not available for '{0}'. Falling back to targeted Delinea lookups. Error: {1}" -f $zoneKey, $_.Exception.Message)
    }
}

function Get-DelineaProfileForAdUser {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$AdUser,

        [Parameter(Mandatory = $true)]
        $Zone,

        [Parameter(Mandatory = $true)]
        [hashtable]$ZoneByDn,

        [switch]$CascadeLookup
    )

    $zoneKey = Get-DelineaZoneKey -Zone $Zone
    $identityKeys = New-DelineaIdentityKeysForAdUser -AdUser $AdUser

    $cached = Get-DelineaCachedProfileByKeys -ZoneKey $zoneKey -IdentityKeys $identityKeys
    if ($cached) {
        if ($cached.PSObject.Properties.Match('__NotFound').Count -gt 0) {
            return $null
        }
        return $cached
    }

    $preloaded = Get-DelineaProfileFromZoneIndex -ZoneKey $zoneKey -IdentityKeys $identityKeys
    if ($preloaded) {
        Set-DelineaCachedProfileByKeys -ZoneKey $zoneKey -IdentityKeys $identityKeys -Profile $preloaded
        return $preloaded
    }

    $candidates = New-Object System.Collections.Generic.List[string]

    if ($AdUser.UserPrincipalName) {
        [void]$candidates.Add([string]$AdUser.UserPrincipalName)
    }

    if ($AdUser.SamAccountName) {
        [void]$candidates.Add([string]$AdUser.SamAccountName)
    }

    if ($AdUser.SamAccountName -and $AdUser.DistinguishedName) {
        $userDomain = Get-DomainFromDistinguishedName -DistinguishedName $AdUser.DistinguishedName
        if ($userDomain) {
            [void]$candidates.Add(("{0}@{1}" -f $AdUser.SamAccountName, $userDomain))
        }
    }

    $candidates = @(
        $candidates |
        Where-Object { $_ -and $_.Trim().Length -gt 0 } |
        Select-Object -Unique
    )

    foreach ($candidate in @($candidates)) {
        $profile = $null

        if ($CascadeLookup) {
            $profile = Get-CdmUserProfileCascade -StartZone $Zone -UserName $candidate -ZoneByDn $ZoneByDn
        } else {
            $profile = Get-CdmUserProfileSafe -Zone $Zone -UserName $candidate
        }

        if ($profile) {
            Set-DelineaCachedProfileByKeys -ZoneKey $zoneKey -IdentityKeys $identityKeys -Profile $profile
            return $profile
        }
    }

    Set-DelineaCachedProfileByKeys -ZoneKey $zoneKey -IdentityKeys $identityKeys -Profile $null
    return $null
}

# Build domain list
$fallbackDomains = Get-FallbackDomainList -ExplicitDomains $Domains

# Resolve AD group
$group = $null
try {
    $group = Resolve-ADGroupCrossDomain -Identity $GroupName -DomainList $fallbackDomains
} catch {
    $group = $null
}

if (-not $group) {
    if ($fallbackDomains -and @($fallbackDomains).Count -gt 0) {
        throw "Failed to resolve group '$GroupName' using domains: $($fallbackDomains -join ', ')"
    }

    throw "Failed to resolve group '$GroupName' in the current domain context, and domain discovery was not available. Specify -Domains for cross-domain resolution."
}

Write-Verbose ("Resolved AD group '{0}'" -f $group.Name)

# Enumerate group members
$members = Get-ADGroupMembersCrossDomain -Group $group -DomainList $fallbackDomains
Write-Verbose ("Enumerated {0} raw group member objects" -f @($members).Count)

# Build field plan
$fieldPlan = Build-FieldPlan -ExplicitFields $Fields -LegacyName:$Name -LegacyEmail:$Email -LegacyAttributes $Attributes
$outProps = $fieldPlan.OutColumns
$adProps = $fieldPlan.AdProps
$colToProp = $fieldPlan.ColumnToAdProp

# Always request these for processing
$requiredForProcessing = @('Enabled', 'AccountExpirationDate', 'UserPrincipalName', 'DistinguishedName', 'SamAccountName', 'SID')
foreach ($rf in $requiredForProcessing) {
    if ($adProps -notcontains $rf) {
        $adProps = @($adProps + $rf)
    }
}

$needsDelineaLookup = Test-NeedsDelineaLookup -Columns $outProps
Initialize-DelineaCaches

$allZones = @()
$resolvedZone = $null
$zoneByDn = @{}

if ($needsDelineaLookup) {
    if (-not $CdmZone) {
        throw "Parameter -CdmZone is required when Delinea-backed fields are requested."
    }

    Import-Module Centrify.DirectControl.PowerShell -ErrorAction Stop

    $allZones = @(Get-CdmZone -ErrorAction Stop)
    if (-not $allZones -or $allZones.Count -eq 0) {
        throw "Get-CdmZone returned no zones."
    }

    $resolvedZone = Resolve-CdmZoneObject -ZoneInput $CdmZone
    $zoneByDn = Build-ZoneLookupMap -AllZones $allZones

    Write-Verbose ("Resolved Delinea zone '{0}' to '{1}'" -f $CdmZone, $resolvedZone.CanonicalName)

    Initialize-DelineaZoneIndex -Zone $resolvedZone
}

# Determine whether structured output is needed
$needsStructured = $false
if ($fieldPlan.UsesExplicit) {
    if (@($outProps).Count -gt 1) { $needsStructured = $true }
} else {
    if ($Name -or $Email -or (@($Attributes).Count -gt 0)) { $needsStructured = $true }
}
if ($Csv -or $Tsv) { $needsStructured = $true }

# Username-only mode
if (-not $needsStructured) {
    $namesOnly = New-Object System.Collections.Generic.List[string]

    $memberList = @($members)
    $memberTotal = $memberList.Count
    $memberIndex = 0

    foreach ($m in $memberList) {
        $memberIndex++

        if (($memberIndex % 50) -eq 0 -or $memberIndex -eq 1 -or $memberIndex -eq $memberTotal) {
            Write-Progress -Activity "Resolving AD group members" `
                -Status ("Processing {0} of {1}" -f $memberIndex, $memberTotal) `
                -PercentComplete (($memberIndex / [math]::Max($memberTotal, 1)) * 100)
        }

        if ($m.objectClass -ne 'user') { continue }
        if (-not $m.DistinguishedName) { continue }

        $u = Get-ADUserCrossDomain -DistinguishedName $m.DistinguishedName -Properties $adProps -FallbackDomains $fallbackDomains
        if (-not $u) { continue }

        if (-not (Test-UserIsActive -UserObject $u -IncludeDisabled:$IncludeDisabled -IncludeExpired:$IncludeExpired)) {
            continue
        }

        if ($u.SamAccountName) {
            [void]$namesOnly.Add([string]$u.SamAccountName)
        }
    }

    Write-Progress -Activity "Resolving AD group members" -Completed
    $namesOnly | Sort-Object -Unique
    exit 0
}

# Structured output
$results = New-Object System.Collections.Generic.List[object]

$memberList = @($members)
$memberTotal = $memberList.Count
$memberIndex = 0

foreach ($m in $memberList) {
    $memberIndex++

    if (($memberIndex % 25) -eq 0 -or $memberIndex -eq 1 -or $memberIndex -eq $memberTotal) {
        Write-Progress -Activity "Resolving AD and Delinea users" `
            -Status ("Processing {0} of {1}" -f $memberIndex, $memberTotal) `
            -PercentComplete (($memberIndex / [math]::Max($memberTotal, 1)) * 100)
    }

    if ($m.objectClass -ne 'user') { continue }
    if (-not $m.DistinguishedName) { continue }

    $u = Get-ADUserCrossDomain -DistinguishedName $m.DistinguishedName -Properties $adProps -FallbackDomains $fallbackDomains
    if (-not $u) { continue }

    if (-not (Test-UserIsActive -UserObject $u -IncludeDisabled:$IncludeDisabled -IncludeExpired:$IncludeExpired)) {
        continue
    }

    $delineaProfile = $null
    $delineaStatus = $null
    $missingDelineaAttributes = $false

    if ($needsDelineaLookup) {
        $delineaProfile = Get-DelineaProfileForAdUser -AdUser $u -Zone $resolvedZone -ZoneByDn $zoneByDn -CascadeLookup:$CascadeZoneLookup

        if ($delineaProfile) {
            $delineaStatus = 'Present'
            $missingDelineaAttributes = $false
        } else {
            $delineaStatus = 'Missing profile in Delinea provisioning zone'
            $missingDelineaAttributes = $true
        }
    }

    $row = [ordered]@{}
    foreach ($col in $outProps) {
        switch -Regex ($col) {
            '^(?i)Email$' {
                $row[$col] = Convert-ADValueToDisplayString -Value ($u.mail)
            }

            '^(?i)(OU|OrganizationalUnit)$' {
                $row[$col] = Get-ParentDn -DistinguishedName $u.DistinguishedName
            }

            '^(?i)DelineaZone$' {
                if ($needsDelineaLookup) {
                    if ($resolvedZone.CanonicalName) {
                        $row[$col] = [string]$resolvedZone.CanonicalName
                    } else {
                        $row[$col] = [string]$resolvedZone.Name
                    }
                } else {
                    $row[$col] = $null
                }
            }

            '^(?i)UnixLogin$' {
                if ($delineaProfile -and $delineaProfile.PSObject.Properties.Match('Name').Count -gt 0) {
                    $row[$col] = Convert-DelineaValueToDisplayString -Value $delineaProfile.Name
                } else {
                    $row[$col] = $null
                }
            }

            '^(?i)(UnixUid|UidNumber)$' {
                if ($delineaProfile -and $delineaProfile.PSObject.Properties.Match('Uid').Count -gt 0) {
                    $row[$col] = Convert-DelineaValueToDisplayString -Value $delineaProfile.Uid
                } else {
                    $row[$col] = $null
                }
            }

            '^(?i)PrimaryGroupId$' {
                if ($delineaProfile -and $delineaProfile.PSObject.Properties.Match('PrimaryGroupId').Count -gt 0) {
                    $row[$col] = Convert-DelineaValueToDisplayString -Value $delineaProfile.PrimaryGroupId
                } else {
                    $row[$col] = $null
                }
            }

            '^(?i)DelineaStatus$' {
                $row[$col] = $delineaStatus
            }

            '^(?i)MissingDelineaAttributes$' {
                $row[$col] = $missingDelineaAttributes
            }

            default {
                $adProp = $colToProp[$col]
                $row[$col] = Convert-ADValueToDisplayString -Value ($u.$adProp)
            }
        }
    }

    [void]$results.Add([pscustomobject]$row)
}

Write-Progress -Activity "Resolving AD and Delinea users" -Completed

$sorted = $results | Sort-Object -Property SamAccountName -Unique

if ($Csv) {
    $sorted | Select-Object -Property $outProps | ConvertTo-Csv -NoTypeInformation
    exit 0
}

if ($Tsv) {
    $selected = $sorted | Select-Object -Property $outProps
    ConvertTo-Tsv -InputObject $selected -Properties $outProps
    exit 0
}

$sorted | Select-Object -Property $outProps