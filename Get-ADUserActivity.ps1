 <#
.INFO
  Synopsis:
    Query Active Directory user activity and export selected fields (CSV/TSV), optionally filtering by last-logon staleness.

  Description:
    Queries Active Directory users within a domain or an OU search base and outputs requested fields.

    Activity fields:
      - LastLogon is computed from lastLogonTimestamp (replicated, may lag).
      - Modified is read from whenChanged.

    Cutoff behavior:
      - When -Cutoff is specified, results include users whose LastLogon is:
          * missing (never or not recorded), unless -ExcludeNeverLoggedIn is set
          * older than (Now - Cutoff)

    Account filtering:
      - By default, disabled and expired accounts are excluded.
      - Use -IncludeDisabled and/or -IncludeExpired to include them.

    Field selection:
      - -Fields defines output columns exactly. No implicit columns are added.
      - Computed aliases supported:
          * LastLogon
          * Modified
          * AccountState (computed from Enabled + AccountExpirationDate)
      - Common alias:
          * Email (maps to mail)
      - Any other token is treated as an AD attribute name (example: mail, department, employeeID).

    Output:
      - Default: objects
      - -Csv or -Tsv: outputs delimited text
      - -OutFile: writes the chosen output format to a file (still outputs to stdout)

  Parameters:
    -Domain
      Domain DNS name or domain controller to query.

    -SearchBase
      Distinguished name (DN) of an OU/container used as query root (subtree).

    -Domains
      One or more domains/domain controllers used as fallback targets for query execution.

    -Cutoff
      Staleness cutoff in compact form: <number><unit>
        Units:
          h = hours
          d = days
          w = weeks
          m = months (30 days)
          y = years (365 days)
      Examples: 24h, 30d, 6m, 1y

    -ExcludeNeverLoggedIn
      When -Cutoff is set, excludes accounts with no lastLogonTimestamp value.

    -IncludeDisabled
      Include disabled accounts.

    -IncludeExpired
      Include expired accounts (AccountExpirationDate in the past).

    -Fields
      Output columns / lookup fields. No implicit columns are added.
      Accepted forms:
        -Fields mail,LastLogon,Modified,AccountState
        -Fields "mail,LastLogon,Modified,AccountState"
        -Fields mail LastLogon Modified AccountState

    -Csv / -Tsv
      Output as CSV or TSV.

    -OutFile
      Output file path.

  Examples:
    .\Get-ADUserActivity.ps1 -SearchBase "OU=Users,DC=example,DC=com" -Cutoff 6m -Fields mail,LastLogon,Modified,AccountState -Tsv -OutFile .\users.tsv
    .\Get-ADUserActivity.ps1 -Domain example.com -Fields SamAccountName,mail,LastLogon -Csv -OutFile .\users.csv
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
    [object]$Fields,

    [Parameter(Mandatory = $false)]
    [switch]$Csv,

    [Parameter(Mandatory = $false)]
    [switch]$Tsv,

    [Parameter(Mandatory = $false)]
    [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Csv -and $Tsv) {
    throw "Parameters -Csv and -Tsv are mutually exclusive."
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "Required module 'ActiveDirectory' not found. Install RSAT Active Directory tools and retry."
}
Import-Module ActiveDirectory -ErrorAction Stop

function Convert-CutoffToTimeSpan {
    param([Parameter(Mandatory = $true)][string]$Value)

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

function Resolve-FieldList {
    param([AllowNull()][object]$RawFields)

    if ($null -eq $RawFields) { return @() }

    $tokens = @()

    foreach ($item in @($RawFields)) {
        if ($null -eq $item) { continue }

        $s = ([string]$item).Trim()
        if ($s.Length -eq 0) { continue }

        if ($s -match ',') {
            $tokens += ($s -split '\s*,\s*')
        } else {
            $tokens += $s
        }
    }

    $tokens =
        @($tokens) |
        ForEach-Object { ([string]$_).Trim() } |
        Where-Object { $_ -and $_.Length -gt 0 } |
        Select-Object -Unique

    return @($tokens)
}

function Get-DomainFromDistinguishedName {
    param([Parameter(Mandatory = $true)][string]$DistinguishedName)

    $dcParts = @()
    foreach ($part in ($DistinguishedName -split ',')) {
        $p = $part.Trim()
        if ($p -match '^(?i)DC=(.+)$') { $dcParts += $Matches[1] }
    }

    if (@($dcParts).Count -gt 0) { return ($dcParts -join '.') }
    return $null
}

function Get-FallbackDomainList {
    param([string[]]$ExplicitDomains)

    $explicit =
        @($ExplicitDomains) |
        Where-Object { $_ -and ([string]$_).Trim().Length -gt 0 } |
        ForEach-Object { ([string]$_).Trim() } |
        Select-Object -Unique

    if (@($explicit).Count -gt 0) { return @($explicit) }

    try {
        $forest = Get-ADForest -ErrorAction Stop
        return @(@($forest.Domains) | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Select-Object -Unique)
    } catch {
        return @()
    }
}

function Get-ComputedLastLogon {
    param([Parameter(Mandatory = $true)]$User)

    $llt = $User.lastLogonTimestamp
    if ($null -eq $llt -or $llt -eq 0) { return $null }
    return [DateTime]::FromFileTime([Int64]$llt)
}

function Test-UserIsActive {
    param(
        [Parameter(Mandatory = $true)]$UserObject,
        [Parameter(Mandatory = $true)][DateTime]$Now,
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
            if ($aed -is [DateTime] -and $aed -lt $Now) { return $false }
        }
    }

    return $true
}

function Get-AccountState {
    param(
        [Parameter(Mandatory = $true)]$User,
        [Parameter(Mandatory = $true)][DateTime]$Now
    )

    $enabled = $true
    if ($User.PSObject.Properties.Match('Enabled').Count -gt 0) {
        $enabled = ($User.Enabled -eq $true)
    }

    $expired = $false
    if ($User.PSObject.Properties.Match('AccountExpirationDate').Count -gt 0) {
        $aed = $User.AccountExpirationDate
        if ($aed -is [DateTime]) { $expired = ($aed -lt $Now) }
    }

    if ($enabled -and -not $expired) { return 'Active' }
    if (-not $enabled -and -not $expired) { return 'Disabled' }
    if ($enabled -and $expired) { return 'Expired' }
    return 'Disabled+Expired'
}

function Build-PropertyRequestList {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$OutputColumns,

        [Parameter(Mandatory = $true)]
        [switch]$NeedsCutoff,

        [Parameter(Mandatory = $true)]
        [switch]$NeedsFiltering
    )

    $props = @()

    foreach ($c in @($OutputColumns)) {
        switch -Regex ($c) {
            '^(?i)LastLogon$'    { if ($props -notcontains 'lastLogonTimestamp') { $props += 'lastLogonTimestamp' } }
            '^(?i)Modified$'     { if ($props -notcontains 'whenChanged') { $props += 'whenChanged' } }
            '^(?i)AccountState$' { if ($props -notcontains 'Enabled') { $props += 'Enabled' }; if ($props -notcontains 'AccountExpirationDate') { $props += 'AccountExpirationDate' } }
            '^(?i)Email$'        { if ($props -notcontains 'mail') { $props += 'mail' } }
            default              { if ($props -notcontains $c) { $props += $c } }
        }
    }

    if ($NeedsFiltering) {
        if ($props -notcontains 'Enabled') { $props += 'Enabled' }
        if ($props -notcontains 'AccountExpirationDate') { $props += 'AccountExpirationDate' }
    }

    if ($NeedsCutoff) {
        if ($props -notcontains 'lastLogonTimestamp') { $props += 'lastLogonTimestamp' }
    }

    return @($props | Select-Object -Unique)
}

function ConvertTo-Tsv {
    param(
        [Parameter(Mandatory = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]$Properties
    )

    $props = @($Properties)
    if (@($props).Count -eq 0) {
        throw "Internal error: TSV property list is empty."
    }

    $rows = @($InputObject)

    $escape = {
        param([object]$v)
        if ($null -eq $v) { return '' }
        $s = [string]$v
        if ($s -match '[\t\r\n"]') {
            return '"' + ($s -replace '"', '""') + '"'
        }
        return $s
    }

    $lines = @()
    $lines += ($props -join "`t")

    foreach ($row in $rows) {
        $vals = foreach ($p in $props) { & $escape ($row.$p) }
        $lines += ($vals -join "`t")
    }

    return ($lines -join "`r`n")
}

# Determine target domains to try
$now = Get-Date
$fallbackDomains = Get-FallbackDomainList -ExplicitDomains $Domains

$tryList = @()

if ($SearchBase -and $SearchBase.Trim()) {
    $dnDomain = Get-DomainFromDistinguishedName -DistinguishedName $SearchBase
    if ($dnDomain) { $tryList += $dnDomain }
}

if ($Domain -and $Domain.Trim()) { $tryList += $Domain.Trim() }
$tryList += @($fallbackDomains)

$tryList =
    @($tryList) |
    Where-Object { $_ -and ([string]$_).Trim().Length -gt 0 } |
    ForEach-Object { ([string]$_).Trim() } |
    Select-Object -Unique

if (@($tryList).Count -eq 0) {
    throw "No domain context available. Specify -Domain, -SearchBase, or -Domains."
}

# Resolve output columns
$resolvedFields = Resolve-FieldList -RawFields $Fields

if (@($resolvedFields).Count -eq 0) {
    # Default view only when -Fields not provided
    $resolvedFields = @(
        'SamAccountName','Name','mail','Enabled','AccountState',
        'AccountExpirationDate','LastLogon','Modified','DistinguishedName'
    )
}

# Cutoff
$cutoffDate = $null
if ($Cutoff -and $Cutoff.Trim()) {
    $cutoffDate = $now.Add(-(Convert-CutoffToTimeSpan -Value $Cutoff))
}

Write-Verbose ("Resolved Fields: {0}" -f ($resolvedFields -join ', '))

$needsCutoff = [bool]($cutoffDate -ne $null)
$needsFiltering = $true

$adProps = Build-PropertyRequestList -OutputColumns $resolvedFields -NeedsCutoff:$needsCutoff -NeedsFiltering:$needsFiltering

# Query users
$users = $null
$lastErr = $null

foreach ($srv in @($tryList)) {
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
    if ($lastErr) { throw "Failed to query users. Last error: $($lastErr.Exception.Message)" }
    throw "Failed to query users."
}

# Filter and shape output
$results = @()

foreach ($u in @($users)) {
    if (-not (Test-UserIsActive -UserObject $u -Now $now -IncludeDisabled:$IncludeDisabled -IncludeExpired:$IncludeExpired)) { continue }

    if ($cutoffDate) {
        $ll = Get-ComputedLastLogon -User $u
        if ($null -eq $ll) {
            if ($ExcludeNeverLoggedIn) { continue }
        } else {
            if ($ll -ge $cutoffDate) { continue }
        }
    }

    $row = [ordered]@{}
    foreach ($col in @($resolvedFields)) {
        switch -Regex ($col) {
            '^(?i)LastLogon$'    { $row[$col] = Get-ComputedLastLogon -User $u; break }
            '^(?i)Modified$'     { $row[$col] = $u.whenChanged; break }
            '^(?i)AccountState$' { $row[$col] = Get-AccountState -User $u -Now $now; break }
            '^(?i)Email$'        { $row[$col] = $u.mail; break }
            default              { $row[$col] = $u.$col; break }
        }
    }

    $results += [pscustomobject]$row
}

# Output
if ($Csv) {
    $text = (@($results | Select-Object -Property $resolvedFields | ConvertTo-Csv -NoTypeInformation)) -join "`r`n"
    if ($OutFile) { Set-Content -Path $OutFile -Value $text -Encoding utf8 }
    $text
    return
}

if ($Tsv) {
    $selected = @($results | Select-Object -Property $resolvedFields)
    $text = ConvertTo-Tsv -InputObject $selected -Properties $resolvedFields
    if ($OutFile) { Set-Content -Path $OutFile -Value $text -Encoding utf8 }
    $text
    return
}

$results | Select-Object -Property $resolvedFields
