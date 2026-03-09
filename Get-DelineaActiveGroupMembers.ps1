<#
.INFO
  Synopsis:
    Enumerate active AD group members across domains and enrich them with Delinea zone attributes.

  Description:
    Retrieves members for the specified AD group, resolves nested group members recursively
    across domains and forests, filters to active AD users by default, and enriches the
    results with Delinea user profile attributes from a specified Delinea zone.

    AD behavior:
      - Cross-domain group and user resolution is supported
      - Nested groups are expanded recursively
      - Disabled users are excluded by default
      - Expired users are excluded by default
      - Use -IncludeDisabled and/or -IncludeExpired to override

    Delinea behavior:
      - -CdmZone is required
      - The zone may be specified by exact name, canonical path, or distinguished name
      - By default, user profile lookup is attempted only in the specified zone
      - Use -CascadeZoneLookup to walk parent zones until a profile is found

    Field selection:
      - AD-backed fields continue to work through -Fields or legacy -Name, -Email, -Attributes
      - Delinea enrichment fields can be requested through -Fields:
          * DelineaZone
          * UnixLogin
          * UnixUid
          * UidNumber
          * PrimaryGroupId

    Output:
      - Default output is PowerShell objects
      - -Csv outputs CSV
      - -Tsv outputs TSV

  Parameters:
    -GroupName
      Group name, sAMAccountName, CN, or distinguished name.

    -Domains
      One or more domains or domain controllers to query.

    -CdmZone
      Delinea zone name, canonical path, or distinguished name.

    -CascadeZoneLookup
      Walk parent zones when a Delinea profile is not found in the specified zone.

    -Fields
      Optional explicit output columns.
      Examples:
        SamAccountName,Name,Email,uidNumber,DelineaZone,UnixLogin,UnixUid,PrimaryGroupId

    -Name / -Email / -Attributes
      Legacy field selection.

    -IncludeDisabled
      Include disabled user accounts.

    -IncludeExpired
      Include expired user accounts.

    -Csv / -Tsv
      Output as CSV or TSV.

  Examples:
    .\Get-DelineaActiveGroupMembers.ps1 "Domain Users" -CdmZone "Global Zone/Linux"

    .\Get-DelineaActiveGroupMembers.ps1 "Domain Users" `
      -CdmZone "Global Zone/Linux" `
      -Fields SamAccountName,Name,Email,DelineaZone,UnixLogin,UnixUid,PrimaryGroupId `
      -Tsv

    .\Get-DelineaActiveGroupMembers.ps1 "Example Group" `
      -Domains "example.com","child.example.com" `
      -CdmZone "Global Zone/Engineering" `
      -CascadeZoneLookup `
      -IncludeDisabled
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Alias('Group')]
    [string]$GroupName,

    [Parameter(Mandatory = $false)]
    [string[]]$Domains = @(),

    [Parameter(Mandatory = $true)]
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
Import-Module Centrify.DirectControl.PowerShell -ErrorAction Stop

# Ensure DistinguishedName is requested when OU or OrganizationalUnit is included in -Fields
try {
    if ($Fields) {
        $fieldTokens = @()
        foreach ($f in @($Fields)) {
            if ($null -eq $f) { continue }
            $s = ([string]$f).Trim()
            if (-not $s) { continue }
            if ($s -match ',') { $fieldTokens += ($s -split '\s*,\s*') } else { $fieldTokens += $s }
        }
        $fieldTokens = @(
            $fieldTokens |
            ForEach-Object { ([string]$_).Trim() } |
            Where-Object { $_ } |
            Select-Object -Unique
        )

        if ($fieldTokens -match '^(?i)(OU|OrganizationalUnit)$') {
            if ($Attributes -notcontains 'DistinguishedName') { $Attributes += 'DistinguishedName' }
        }
    }
} catch {
    # Best-effort only
}

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
            ForEach-Object { ([string]$_).Trim() }
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
        # ignore
    }

    return @()
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

function Normalize-UniqueNonEmpty {
    param([string[]]$Values)
    if (-not $Values) { return @() }
    $Values |
        Where-Object { $_ -and $_.Trim().Length -gt 0 } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique
}

function Convert-ADValueToDisplayString {
    <#
      Normalizes AD property values for table, CSV, or TSV output.
      - Multi-valued collections become a '; ' joined string.
      - Byte arrays become "BINARY (N bytes)".
    #>
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [byte[]]) {
        return ("BINARY ({0} bytes)" -f $Value.Length)
    }

    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
        $items = @()
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            if ($item -is [byte[]]) { $items += ("BINARY ({0} bytes)" -f $item.Length) }
            else { $items += [string]$item }
        }
        return ($items -join '; ')
    }

    return [string]$Value
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
                '^(?i)samaccountname$'      { & $addColumn 'SamAccountName' 'SamAccountName' }
                '^(?i)name$'                { & $addColumn 'Name' 'Name' }
                '^(?i)email$'               { & $addColumn 'Email' 'mail' }
                '^(?i)(OU|OrganizationalUnit)$' { & $addColumn 'OU' 'DistinguishedName' }
                '^(?i)DelineaZone$'         { & $addColumn 'DelineaZone' $null }
                '^(?i)UnixLogin$'           { & $addColumn 'UnixLogin' $null }
                '^(?i)(UnixUid|UidNumber)$' { & $addColumn 'UnixUid' $null }
                '^(?i)PrimaryGroupId$'      { & $addColumn 'PrimaryGroupId' $null }
                default                     { & $addColumn $f $f }
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
            '^(?i)(OU|OrganizationalUnit)$' { & $addColumn 'OU' 'DistinguishedName' | Out-Null }
            default                         { & $addColumn $p $p | Out-Null }
        }
    }

    return [pscustomobject]@{
        OutColumns     = [string[]]$outColumns
        AdProps        = [string[]]$adProps
        ColumnToAdProp = $columnToAdProp
        UsesExplicit   = $false
    }
}

function Test-UserIsActive {
    <#
      Returns $true if the account should be included, based on Enabled and expiration filters.
    #>
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

    # Exact distinguished name
    $byDn = @(
        $allZones | Where-Object {
            $_.DistinguishedName -and $_.DistinguishedName -eq $ZoneInput
        }
    )
    if ($byDn.Count -eq 1) { return $byDn[0] }
    if ($byDn.Count -gt 1) {
        throw "Multiple Delinea zones matched distinguished name '$ZoneInput'."
    }

    # Exact canonical path, normalized for slash direction and trailing slash
    $byCanonical = @(
        $allZones | Where-Object {
            $_.CanonicalName -and
            (($_.CanonicalName -replace '\\', '/').Trim().Trim('/')) -eq $normalizedInput
        }
    )
    if ($byCanonical.Count -eq 1) { return $byCanonical[0] }
    if ($byCanonical.Count -gt 1) {
        throw "Multiple Delinea zones matched canonical path '$ZoneInput'."
    }

    # Exact leaf name
    $byName = @(
        $allZones | Where-Object {
            $_.Name -and $_.Name -eq $ZoneInput
        }
    )
    if ($byName.Count -eq 1) { return $byName[0] }
    if ($byName.Count -gt 1) {
        $matches = ($byName | Select-Object -ExpandProperty CanonicalName) -join ', '
        throw "Multiple Delinea zones matched name '$ZoneInput'. Use a canonical path instead. Matches: $matches"
    }

    # Exact leaf name from the provided path
    $leafName = ($normalizedInput -split '/')[(-1)]
    if ($leafName) {
        $byLeaf = @(
            $allZones | Where-Object {
                $_.Name -and $_.Name -eq $leafName
            }
        )
        if ($byLeaf.Count -eq 1) { return $byLeaf[0] }
        if ($byLeaf.Count -gt 1) {
            $matches = ($byLeaf | Select-Object -ExpandProperty CanonicalName) -join ', '
            throw "Multiple Delinea zones matched leaf name '$leafName'. Use the exact canonical path instead. Matches: $matches"
        }
    }

    # Fuzzy canonical match
    $byCanonicalLike = @(
        $allZones | Where-Object {
            $_.CanonicalName -and
            (($_.CanonicalName -replace '\\', '/').Trim().Trim('/')) -like "*$normalizedInput*"
        }
    )
    if ($byCanonicalLike.Count -eq 1) { return $byCanonicalLike[0] }
    if ($byCanonicalLike.Count -gt 1) {
        $matches = ($byCanonicalLike | Select-Object -ExpandProperty CanonicalName) -join ', '
        throw "Multiple Delinea zones loosely matched '$ZoneInput'. Matches: $matches"
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
        return Get-CdmUserProfile -Zone $Zone -User $UserName -ErrorAction Stop
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

    $candidates = New-Object System.Collections.Generic.List[string]

    if ($AdUser.UserPrincipalName) {
        [void]$candidates.Add([string]$AdUser.UserPrincipalName)
    }

    if ($AdUser.SamAccountName) {
        [void]$candidates.Add([string]$AdUser.SamAccountName)
    }

    $uniqueCandidates = @(
        $candidates |
        Where-Object { $_ -and $_.Trim().Length -gt 0 } |
        Select-Object -Unique
    )

    foreach ($candidate in $uniqueCandidates) {
        if ($CascadeLookup) {
            $profile = Get-CdmUserProfileCascade -StartZone $Zone -UserName $candidate -ZoneByDn $ZoneByDn
        } else {
            $profile = Get-CdmUserProfileSafe -Zone $Zone -UserName $candidate
        }

        if ($profile) { return $profile }
    }

    return $null
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

# Build domain list
$fallbackDomains = Get-FallbackDomainList -ExplicitDomains $Domains

# Resolve AD group across domains
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

# Resolve Delinea zone
$allZones = @(Get-CdmZone -ErrorAction Stop)
if (-not $allZones -or $allZones.Count -eq 0) {
    throw "Get-CdmZone returned no zones."
}

$resolvedZone = Resolve-CdmZoneObject -ZoneInput $CdmZone
$zoneByDn = Build-ZoneLookupMap -AllZones $allZones

$members = Get-ADGroupMembersCrossDomain -Group $group -DomainList $fallbackDomains

# Build field plan
$fieldPlan = Build-FieldPlan -ExplicitFields $Fields -LegacyName:$Name -LegacyEmail:$Email -LegacyAttributes $Attributes
$outProps = $fieldPlan.OutColumns
$adProps = $fieldPlan.AdProps
$colToProp = $fieldPlan.ColumnToAdProp

# Always request these for AD filtering and Delinea lookup
$requiredForProcessing = @('Enabled', 'AccountExpirationDate', 'UserPrincipalName', 'DistinguishedName', 'SamAccountName')
foreach ($rf in $requiredForProcessing) {
    if ($adProps -notcontains $rf) {
        $adProps = @($adProps + $rf)
    }
}

# Determine whether structured output is needed
$needsStructured = $false
if ($fieldPlan.UsesExplicit) {
    if (@($outProps).Count -gt 1) { $needsStructured = $true }
} else {
    if ($Name -or $Email -or (@($Attributes).Count -gt 0)) { $needsStructured = $true }
}
if ($Csv -or $Tsv) { $needsStructured = $true }

# Username-only mode if nothing else is requested
if (-not $needsStructured) {
    $namesOnly = New-Object System.Collections.Generic.List[string]

    foreach ($m in @($members)) {
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

    $namesOnly | Sort-Object -Unique
    exit 0
}

# Structured output
$results = New-Object System.Collections.Generic.List[object]

foreach ($m in @($members)) {
    if ($m.objectClass -ne 'user') { continue }
    if (-not $m.DistinguishedName) { continue }

    $u = Get-ADUserCrossDomain -DistinguishedName $m.DistinguishedName -Properties $adProps -FallbackDomains $fallbackDomains
    if (-not $u) { continue }

    if (-not (Test-UserIsActive -UserObject $u -IncludeDisabled:$IncludeDisabled -IncludeExpired:$IncludeExpired)) {
        continue
    }

    $delineaProfile = Get-DelineaProfileForAdUser -AdUser $u -Zone $resolvedZone -ZoneByDn $zoneByDn -CascadeLookup:$CascadeZoneLookup

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
                if ($resolvedZone.CanonicalName) {
                    $row[$col] = [string]$resolvedZone.CanonicalName
                } else {
                    $row[$col] = [string]$resolvedZone.Name
                }
            }

            '^(?i)UnixLogin$' {
                if ($delineaProfile) {
                    if ($delineaProfile.PSObject.Properties.Match('Name').Count -gt 0) {
                        $row[$col] = Convert-DelineaValueToDisplayString -Value $delineaProfile.Name
                    } else {
                        $row[$col] = $null
                    }
                } else {
                    $row[$col] = $null
                }
            }

            '^(?i)(UnixUid|UidNumber)$' {
                if ($delineaProfile) {
                    if ($delineaProfile.PSObject.Properties.Match('Uid').Count -gt 0) {
                        $row[$col] = Convert-DelineaValueToDisplayString -Value $delineaProfile.Uid
                    } else {
                        $row[$col] = $null
                    }
                } else {
                    $row[$col] = $null
                }
            }

            '^(?i)PrimaryGroupId$' {
                if ($delineaProfile) {
                    if ($delineaProfile.PSObject.Properties.Match('PrimaryGroupId').Count -gt 0) {
                        $row[$col] = Convert-DelineaValueToDisplayString -Value $delineaProfile.PrimaryGroupId
                    } else {
                        $row[$col] = $null
                    }
                } else {
                    $row[$col] = $null
                }
            }

            default {
                $adProp = $colToProp[$col]
                $row[$col] = Convert-ADValueToDisplayString -Value ($u.$adProp)
            }
        }
    }

    [void]$results.Add([pscustomobject]$row)
}

# Sort and unique by SamAccountName
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