<#
.INFO
  Synopsis:
    List Active Directory user last-logon and modification activity for a domain or OU, optionally filtering by a staleness cutoff.

  Description:
    Queries Active Directory for users in a target scope and outputs activity fields such as:
      - LastLogon (derived from lastLogonTimestamp - replicated, may lag)
      - Modified (whenChanged)

    Scope selection:
      - Use -SearchBase with an OU distinguished name to target a specific OU subtree.
      - Use -Domain to target an entire domain.

    Cross-domain behavior:
      - When -Domains is provided, it is used as the fallback domain list.
      - When -Domains is omitted, the script attempts to discover domains from the current forest.

    Account filtering:
      - By default, disabled users and expired users are excluded:
          * Enabled -eq $false
          * AccountExpirationDate is set and < now
      - Use -IncludeDisabled and/or -IncludeExpired to override.

    Cutoff filtering:
      - Use -Cutoff with values like 30d, 6m, 12w, 1y, 24h.
      - When -Cutoff is set, output includes accounts whose last logon is:
          - missing (never or not recorded), unless -ExcludeNeverLoggedIn is set
          - older than (Now - Cutoff)

    Field selection:
      - If -Fields is provided, it defines output columns and which AD attributes are requested.
        Special aliases:
          * Email      -> AD attribute mail, output column name Email
          * LastLogon  -> computed from lastLogonTimestamp
          * Modified   -> AD attribute whenChanged, output column name Modified
          * AccountState -> computed from Enabled + AccountExpirationDate
      - If -Fields is not provided, a default activity view is returned:
          SamAccountName,Name,Email,Enabled,AccountState,AccountExpirationDate,LastLogon,Modified,DistinguishedName

    Output behavior:
      - By default, outputs objects.
      - Use -Csv or -Tsv to output delimited text.

  Parameters:
    -Domain
      Domain DNS name or domain controller to query, for example: example.com

    -SearchBase
      Distinguished name of an OU (or container) used as the query root.
      Example: OU=Users,DC=example,DC=com
      Search scope is Subtree.

    -Domains
      One or more domains or domain controllers to use as a fallback list for queries.

    -Cutoff
      Staleness cutoff in compact form: <number><unit>
        Units:
          h = hours
          d = days
          w = weeks
          m = months (30 days each)
          y = years (365 days each)
      Examples: 24h, 30d, 6m, 12w, 1y

    -ExcludeNeverLoggedIn
      When -Cutoff is set, excludes accounts where last logon is missing.

    -IncludeDisabled
      Include disabled user accounts.

    -IncludeExpired
      Include expired user accounts (AccountExpirationDate in the past).

    -Fields
      Optional. Explicit output columns / lookup fields.
      Examples: SamAccountName,Name,Email,LastLogon,Modified,whenCreated,department

    -Csv / -Tsv
      Output as CSV or TSV.

  Examples:
    # Entire domain, default fields (disabled/expired excluded by default)
    .\Get-ADUserActivity.ps1 -Domain example.com

    # OU subtree with staleness cutoff
    .\Get-ADUserActivity.ps1 -SearchBase "OU=Users,DC=example,DC=com" -Cutoff 6m

    # Include expired accounts explicitly
    .\Get-ADUserActivity.ps1 -Domain example.com -IncludeExpired

    # Explicit fields, TSV output
    .\Get-ADUserActivity.ps1 -Domain example.com -Fields SamAccountName,Email,LastLogon,Modified,AccountState -Tsv
#>

[CmdletBinding(DefaultParameterSetName = 'ByDomain')]
param(
    [Parameter(ParameterSetName = 'ByDomain', Mandatory = $false)]
    [string]$Domain,

    [Parameter(ParameterSetName = 'BySearchBase', Mandatory = $false)]
    [string]$SearchBase,

    [Parameter(Mandatory = $false)]
    [string[]]$Domains = @(),

    [Parameter(Mandatory = $false)]
    [string]$Cutoff,

    [Parameter(Mandatory = $false)]
    [switch]$ExcludeNeverLoggedIn,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabled,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeExpired,

    [Parameter(Mandatory = $false)]
    [string[]]$Fields = @(),

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

    if (@($dcParts).Count -gt 0) {
        return ($dcParts -join '.')
    }

    return $null
}

function Get-FallbackDomainList {
    param(
        [Parameter(Mandatory=$false)]
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

function Normalize-UniqueNonEmpty {
    param([string[]]$Values)
    if (-not $Values) { return @() }
    $Values |
        Where-Object { $_ -and $_.Trim().Length -gt 0 } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique
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
            if ($item -is [byte[]]) { $items += ("BINARY ({0} bytes)" -f $item.Length) }
            else { $items += [string]$item }
        }
        return ($items -join '; ')
    }

    return [string]$Value
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

function Parse-CutoffToTimeSpan {
    param([Parameter(Mandatory=$true)][string]$Value)

    $v = $Value.Trim()
    if ($v -notmatch '^(?<n>\d+)\s*(?<u>[hdwmyHDWMY])$') {
        throw "Invalid -Cutoff '$Value'. Expected formats like 24h, 30d, 12w, 6m, 1y."
    }

    $n = [int]$Matches['n']
    $u = $Matches['u'].ToLowerInvariant()

    switch ($u) {
        'h' { return [TimeSpan]::FromHours($n) }
        'd' { return [TimeSpan]::FromDays($n) }
        'w' { return [TimeSpan]::FromDays(7 * $n) }
        'm' { return [TimeSpan]::FromDays(30 * $n) }
        'y' { return [TimeSpan]::FromDays(365 * $n) }
        default { throw "Unsupported cutoff unit '$u'." }
    }
}

function Test-UserIsActive {
    param(
        [Parameter(Mandatory=$true)]
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

function Get-ComputedLastLogon {
    param([Parameter(Mandatory=$true)][object]$User)

    $llt = $User.lastLogonTimestamp
    if ($null -eq $llt -or $llt -eq 0) { return $null }

    return [DateTime]::FromFileTime([Int64]$llt)
}

function Get-AccountState {
    param([Parameter(Mandatory=$true)][object]$User)

    $enabled = $true
    if ($User.PSObject.Properties.Match('Enabled').Count -gt 0) {
        $enabled = ($User.Enabled -eq $true)
    }

    $expired = $false
    $aed = $null
    if ($User.PSObject.Properties.Match('AccountExpirationDate').Count -gt 0) {
        $aed = $User.AccountExpirationDate
        if ($aed -is [DateTime]) {
            $expired = ($aed -lt (Get-Date))
        }
    }

    if ($enabled -and -not $expired) { return 'Active' }
    if (-not $enabled -and -not $expired) { return 'Disabled' }
    if ($enabled -and $expired) { return 'Expired' }
    return 'Disabled+Expired'
}

function Build-FieldPlan {
    param([string[]]$ExplicitFields)

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

    if (@($explicit).Count -gt 0) {
        foreach ($f in $explicit) {
            switch -Regex ($f) {
                '^(?i)samaccountname$' { & $addColumn 'SamAccountName' 'SamAccountName' }
                '^(?i)name$'           { & $addColumn 'Name' 'Name' }
                '^(?i)email$'          { & $addColumn 'Email' 'mail' }
                '^(?i)modified$'       { & $addColumn 'Modified' 'whenChanged' }
                '^(?i)lastlogon$'      { & $addColumn 'LastLogon' 'lastLogonTimestamp' }
                '^(?i)accountstate$'   { & $addColumn 'AccountState' 'Enabled' }
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

    # Default activity view
    & $addColumn 'SamAccountName' 'SamAccountName' | Out-Null
    & $addColumn 'Name' 'Name' | Out-Null
    & $addColumn 'Email' 'mail' | Out-Null
    & $addColumn 'Enabled' 'Enabled' | Out-Null
    & $addColumn 'AccountState' 'Enabled' | Out-Null
    & $addColumn 'AccountExpirationDate' 'AccountExpirationDate' | Out-Null
    & $addColumn 'LastLogon' 'lastLogonTimestamp' | Out-Null
    & $addColumn 'Modified' 'whenChanged' | Out-Null
    & $addColumn 'DistinguishedName' 'DistinguishedName' | Out-Null

    return [pscustomobject]@{
        OutColumns     = [string[]]$outColumns
        AdProps        = [string[]]$adProps
        ColumnToAdProp = $columnToAdProp
        UsesExplicit   = $false
    }
}

# Domain list (fallback)
$fallbackDomains = Get-FallbackDomainList -ExplicitDomains $Domains

# Try list for the query:
# - If SearchBase is set, first try DN-derived domain
# - If Domain is set, prefer it
$tryList = New-Object System.Collections.Generic.List[string]

if ($SearchBase) {
    $dnDomain = Get-DomainFromDistinguishedName -DistinguishedName $SearchBase
    if ($dnDomain) { [void]$tryList.Add($dnDomain) }
}

if ($Domain -and $Domain.Trim()) {
    $d = $Domain.Trim()
    if (-not $tryList.Contains($d)) { [void]$tryList.Add($d) }
}

foreach ($d in @($fallbackDomains)) {
    if (-not $d) { continue }
    $ds = ([string]$d).Trim()
    if (-not $ds) { continue }
    if (-not $tryList.Contains($ds)) { [void]$tryList.Add($ds) }
}

if ($tryList.Count -eq 0) {
    throw "No domain context available. Specify -Domain, -SearchBase, or -Domains."
}

# Cutoff
$cutoffDate = $null
if ($Cutoff -and $Cutoff.Trim()) {
    $span = Parse-CutoffToTimeSpan -Value $Cutoff
    $cutoffDate = (Get-Date).Add(-$span)
}

# Field plan and required properties
$fieldPlan = Build-FieldPlan -ExplicitFields $Fields
$outProps = $fieldPlan.OutColumns
$adProps  = $fieldPlan.AdProps
$colToProp = $fieldPlan.ColumnToAdProp

# Always request these for filtering and computed fields
$required = @('Enabled','AccountExpirationDate','lastLogonTimestamp','whenChanged','mail','SamAccountName','DistinguishedName','Name')
foreach ($r in $required) {
    if ($adProps -notcontains $r) {
        $adProps = @($adProps + $r)
    }
}

# Query users (try domains until success)
$users = $null
$lastErr = $null

foreach ($srv in $tryList) {
    try {
        if ($SearchBase -and $SearchBase.Trim()) {
            $users = Get-ADUser -Server $srv -SearchBase $SearchBase -SearchScope Subtree -Filter * -Properties $adProps -ErrorAction Stop
        } else {
            $users = Get-ADUser -Server $srv -Filter * -Properties $adProps -ErrorAction Stop
        }
        $lastErr = $null
        break
    } catch {
        $lastErr = $_
        continue
    }
}

if (-not $users) {
    if ($lastErr) {
        throw "Failed to query users. Last error: $($lastErr.Exception.Message)"
    }
    throw "Failed to query users."
}

# Apply active filtering (disabled/expired) like the toolkit default
$filtered = New-Object System.Collections.Generic.List[object]
foreach ($u in @($users)) {
    if (-not (Test-UserIsActive -UserObject $u -IncludeDisabled:$IncludeDisabled -IncludeExpired:$IncludeExpired)) {
        continue
    }

    if ($cutoffDate) {
        $ll = Get-ComputedLastLogon -User $u
        if ($null -eq $ll) {
            if ($ExcludeNeverLoggedIn) { continue }
        } else {
            if ($ll -ge $cutoffDate) { continue }
        }
    }

    [void]$filtered.Add($u)
}

# Build output rows with normalization and computed aliases
$results = New-Object System.Collections.Generic.List[object]

foreach ($u in @($filtered)) {
    $row = [ordered]@{}
    foreach ($col in $outProps) {
        switch -Regex ($col) {
            '^(?i)LastLogon$' {
                $row[$col] = Get-ComputedLastLogon -User $u
                break
            }
            '^(?i)Modified$' {
                $row[$col] = $u.whenChanged
                break
            }
            '^(?i)AccountState$' {
                $row[$col] = Get-AccountState -User $u
                break
            }
            default {
                $adProp = $colToProp[$col]
                $row[$col] = Convert-ADValueToDisplayString -Value ($u.$adProp)
                break
            }
        }
    }
    [void]$results.Add([pscustomobject]$row)
}

$sorted =
    if ($outProps -contains 'SamAccountName') {
        $results | Sort-Object -Property SamAccountName
    } else {
        $results
    }

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