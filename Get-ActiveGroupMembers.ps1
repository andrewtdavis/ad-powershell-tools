<#
.INFO
  Synopsis:
    Enumerate AD group members across domains/forests and output selected user fields.

  Description:
    Retrieves group members for the specified group and resolves each member to an AD user.
    Cross-domain lookups are supported by probing the member's DN-derived DNS domain first,
    then falling back to a domain list.

    Field selection:
      - If -Fields is provided, it defines the output columns and which AD attributes are requested.
        Special aliases:
          * Email -> AD attribute mail, output column name Email
      - If -Fields is not provided, output is built from:
          SamAccountName (always), optional -Name, optional -Email, plus -Attributes.

    Account filtering:
      - By default, disabled users and expired users are excluded:
          * Enabled -eq $false
          * AccountExpirationDate is set and < now
      - Use -IncludeDisabled and/or -IncludeExpired to override.

  Parameters:
    -GroupName
      Group name (sAMAccountName, CN, or distinguished name).

    -Domains
      One or more domains or domain controllers to query.

    -Fields
      Optional. Explicit output columns / lookup fields.
      Examples: SamAccountName,Name,Email,uidNumber,employeeID,uid

    -Name / -Email / -Attributes
      Legacy field selection.

    -IncludeDisabled
      Include disabled user accounts.

    -IncludeExpired
      Include expired user accounts (AccountExpirationDate in the past).

    -Csv / -Tsv
      Output as CSV or TSV.

  Examples:
    .\Get-ActiveGroupMembers.ps1 "Domain Users"

    .\Get-ActiveGroupMembers.ps1 "Domain Users" -Fields SamAccountName,Name,Email,uid -Tsv

    .\Get-ActiveGroupMembers.ps1 "Domain Users" -Fields SamAccountName,Email -IncludeDisabled
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Alias('Group')]
    [string]$GroupName,

    [Parameter(Mandatory = $false)]
    [string[]]$Domains = @(),

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

function Get-DomainFromDistinguishedName {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DistinguishedName
    )

    $dcParts = @()
    foreach ($part in ($DistinguishedName -split ',')) {
        $p = $part.Trim()
        if ($p -match '^(?i)DC=(.+)$') {
            $dcParts += $Matches[1]
        }
    }

    if ($dcParts.Count -gt 0) {
        return ($dcParts -join '.')
    }

    return $null
}

function Get-FallbackDomainList {
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$ExplicitDomains
    )

    if ($ExplicitDomains -and $ExplicitDomains.Count -gt 0) {
        return $ExplicitDomains
    }

    try {
        $forest = Get-ADForest -ErrorAction Stop
        if ($forest -and $forest.Domains -and $forest.Domains.Count -gt 0) {
            return [string[]]$forest.Domains
        }
    } catch {
        # ignore
    }

    return @()
}

function Get-ADUserCrossDomain {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DistinguishedName,

        [Parameter(Mandatory=$true)]
        [string[]]$Properties,

        [Parameter(Mandatory=$true)]
        [string[]]$FallbackDomains
    )

    $tryList = New-Object System.Collections.Generic.List[string]

    $dnDomain = Get-DomainFromDistinguishedName -DistinguishedName $DistinguishedName
    if ($dnDomain) { [void]$tryList.Add($dnDomain) }

    if ($FallbackDomains) {
        foreach ($d in $FallbackDomains) {
            if (-not $tryList.Contains($d)) { [void]$tryList.Add($d) }
        }
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
        [Parameter(Mandatory=$true)]
        [string]$Identity,

        [Parameter(Mandatory=$true)]
        [string[]]$DomainList
    )

    if (-not $DomainList -or $DomainList.Count -eq 0) {
        return Get-ADGroup -Identity $Identity -ErrorAction Stop
    }

    foreach ($d in $DomainList) {
        try {
            return Get-ADGroup -Server $d -Identity $Identity -ErrorAction Stop
        } catch {
            continue
        }
    }

    return $null
}

function Get-ADGroupMembersCrossDomain {
    param(
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADGroup]$Group,

        [Parameter(Mandatory=$true)]
        [string[]]$DomainList
    )

    $groupDomain = $null
    if ($Group.DistinguishedName) {
        $groupDomain = Get-DomainFromDistinguishedName -DistinguishedName $Group.DistinguishedName
    }

    $tryList = New-Object System.Collections.Generic.List[string]
    if ($groupDomain) { [void]$tryList.Add($groupDomain) }
    foreach ($d in $DomainList) {
        if (-not $tryList.Contains($d)) { [void]$tryList.Add($d) }
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
        [Parameter(Mandatory=$true)]
        [object[]]$InputObject,

        [Parameter(Mandatory=$true)]
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
      Normalizes AD property values for table/CSV/TSV output.
      - Multi-valued collections become a '; ' joined string.
      - Byte arrays become "BINARY (N bytes)".
    #>
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [byte[]]) {
        return ("BINARY ({0} bytes)" -f $Value.Length)
    }

    # Treat ADPropertyValueCollection and any other IEnumerable (except string) as multi-valued.
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
        param([string]$ColumnName, [string]$AdPropName)
        if (-not $columnToAdProp.Contains($ColumnName)) {
            $columnToAdProp[$ColumnName] = $AdPropName
            [void]$outColumns.Add($ColumnName)
        }
        if ($AdPropName -and $AdPropName.Trim()) {
            [void]$adProps.Add($AdPropName)
        }
    }

    $explicit = Normalize-UniqueNonEmpty -Values $ExplicitFields

    if ($explicit.Count -gt 0) {
        foreach ($f in $explicit) {
            switch -Regex ($f) {
                '^(?i)samaccountname$' { & $addColumn 'SamAccountName' 'SamAccountName' }
                '^(?i)name$'           { & $addColumn 'Name' 'Name' }
                '^(?i)email$'          { & $addColumn 'Email' 'mail' }
                default                { & $addColumn $f $f }
            }
        }

        if (-not $columnToAdProp.Contains('SamAccountName')) {
            $existing = @($outColumns)
            $outColumns.Clear()
            & $addColumn 'SamAccountName' 'SamAccountName' | Out-Null
            foreach ($c in $existing) { if ($c -ne 'SamAccountName') { [void]$outColumns.Add($c) } }
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
        Where-Object { $_ -notin @('SamAccountName','Name','Email','mail') }

    foreach ($p in $extras) {
        & $addColumn $p $p | Out-Null
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
      Returns $true if the account should be included, based on Enabled/expiration filters.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$UserObject,

        [switch]$IncludeDisabled,
        [switch]$IncludeExpired
    )

    if (-not $IncludeDisabled) {
        # Enabled can be $null for some edge cases; treat $false explicitly as disabled.
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

# Build domain list
$fallbackDomains = Get-FallbackDomainList -ExplicitDomains $Domains

# Resolve group across domains
$group = $null
try {
    $group = Resolve-ADGroupCrossDomain -Identity $GroupName -DomainList $fallbackDomains
} catch {
    $group = $null
}

if (-not $group) {
    if ($fallbackDomains -and $fallbackDomains.Count -gt 0) {
        throw "Failed to resolve group '$GroupName' using domains: $($fallbackDomains -join ', ')"
    }
    throw "Failed to resolve group '$GroupName' in the current domain context, and domain discovery was not available. Specify -Domains for cross-domain resolution."
}

$members = Get-ADGroupMembersCrossDomain -Group $group -DomainList $fallbackDomains

# Build field plan (columns + AD properties)
$fieldPlan = Build-FieldPlan -ExplicitFields $Fields -LegacyName:$Name -LegacyEmail:$Email -LegacyAttributes $Attributes
$outProps = $fieldPlan.OutColumns
$adProps = $fieldPlan.AdProps
$colToProp = $fieldPlan.ColumnToAdProp

# Always request these for filtering (even if not output)
$requiredForFilter = @('Enabled', 'AccountExpirationDate')
foreach ($rf in $requiredForFilter) {
    if ($adProps -notcontains $rf) {
        $adProps = @($adProps + $rf)
    }
}

# Determine whether structured output is needed
$needsStructured = $false
if ($fieldPlan.UsesExplicit) {
    if ($outProps.Count -gt 1) { $needsStructured = $true }
} else {
    if ($Name -or $Email -or ($Attributes.Count -gt 0)) { $needsStructured = $true }
}
if ($Csv -or $Tsv) { $needsStructured = $true }

# If still not structured, output usernames only (but still apply active filters)
if (-not $needsStructured) {
    $namesOnly = New-Object System.Collections.Generic.List[string]
    foreach ($m in $members) {
        if ($m.objectClass -ne 'user') { continue }
        if (-not $m.DistinguishedName) { continue }

        $u = Get-ADUserCrossDomain -DistinguishedName $m.DistinguishedName -Properties $adProps -FallbackDomains $fallbackDomains
        if (-not $u) { continue }

        if (-not (Test-UserIsActive -UserObject $u -IncludeDisabled:$IncludeDisabled -IncludeExpired:$IncludeExpired)) {
            continue
        }

        if ($u.SamAccountName) { [void]$namesOnly.Add([string]$u.SamAccountName) }
    }
    $namesOnly | Sort-Object -Unique
    exit 0
}

# Structured output: build rows with normalized display values, apply active filters
$results = New-Object System.Collections.Generic.List[object]

foreach ($m in $members) {
    if ($m.objectClass -ne 'user') { continue }
    if (-not $m.DistinguishedName) { continue }

    $u = Get-ADUserCrossDomain -DistinguishedName $m.DistinguishedName -Properties $adProps -FallbackDomains $fallbackDomains
    if (-not $u) { continue }

    if (-not (Test-UserIsActive -UserObject $u -IncludeDisabled:$IncludeDisabled -IncludeExpired:$IncludeExpired)) {
        continue
    }

    $row = [ordered]@{}
    foreach ($col in $outProps) {
        $adProp = $colToProp[$col]
        $row[$col] = Convert-ADValueToDisplayString -Value ($u.$adProp)
    }

    [void]$results.Add([pscustomobject]$row)
}

# Sort + unique by SamAccountName
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