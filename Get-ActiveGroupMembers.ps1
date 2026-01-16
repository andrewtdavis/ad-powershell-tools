<#
.SYNOPSIS
    Enumerates members of an Active Directory group across multiple domains/forests and outputs selected user fields.

.DESCRIPTION
    Retrieves group members for the specified group (by name or distinguished name) and resolves each member to an AD user.
    Cross-domain lookups are supported by probing the member's DN-derived DNS domain first, then falling back to a domain list.

    Domain list behavior:
      - If -Domains is provided, it is used for group resolution and as fallback for user resolution.
      - If -Domains is not provided, the script attempts to discover domains from the current forest (Get-ADForest).Domains.
        If discovery fails (no connectivity/permissions), the current domain context is used.

    Output formats:
      - Default: one username per line (SamAccountName), sorted unique
      - -Name / -Email / -Attributes: structured output with selected properties
      - -Csv: comma-separated values
      - -Tsv: tab-separated values (with quoting for fields that contain tabs/newlines/quotes)

.PARAMETER GroupName
    Group name (sAMAccountName, CN, or distinguished name). Supports positional usage.

.PARAMETER Domains
    One or more domains or domain controllers to query (e.g., "ad.example.net", "dc01.ad.example.net").
    If omitted, domains are discovered from the current forest when possible.

.PARAMETER Name
    Include the AD 'Name' field in structured output.

.PARAMETER Email
    Include the AD 'mail' attribute in structured output (output column name 'Email').

.PARAMETER Attributes
    Additional AD user attributes to include in structured output.
    Examples: EmployeeID, LastLogonDate, LockedOut, AccountExpirationDate, Enabled, WhenCreated, Department, Title.

.PARAMETER Csv
    Output structured results as CSV. Mutually exclusive with -Tsv.

.PARAMETER Tsv
    Output structured results as TSV. Mutually exclusive with -Csv.

.EXAMPLE
    # Default output: usernames only
    .\Get-ActiveGroupMembers.ps1 "CoreHPC_Base"

.EXAMPLE
    # Include Name and Email, output as TSV with extra attributes
    .\Get-ActiveGroupMembers.ps1 "CoreHPC_Base" -Name -Email -Attributes EmployeeID,LastLogonDate -Tsv

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Alias('Group')]
    [string]$GroupName,

    [Parameter(Mandatory = $false)]
    [string[]]$Domains = @(),

    [Parameter(Mandatory = $false)]
    [switch]$Name,

    [Parameter(Mandatory = $false)]
    [switch]$Email,

    [Parameter(Mandatory = $false)]
    [string[]]$Attributes = @(),

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
    <#
    .SYNOPSIS
        Converts a DN to a DNS domain name, if DC components are present.
    #>
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
    <#
    .SYNOPSIS
        Builds a domain list to try for group/user lookups.
    .DESCRIPTION
        Preference order:
          1) Explicit -Domains parameter
          2) Current forest domains (Get-ADForest).Domains
          3) Empty (meaning: rely on current domain context only)
    #>
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
    <#
    .SYNOPSIS
        Attempts to resolve a group member DN to an AD user across domains.
    .DESCRIPTION
        First attempts lookup in the DN-derived DNS domain, then falls back to a provided domain list.
        Failed attempts are suppressed and the next domain is tried.
    #>
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

    # If no domains to try, rely on current context
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
    <#
    .SYNOPSIS
        Resolves an AD group by identity across domains.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Identity,

        [Parameter(Mandatory=$true)]
        [string[]]$DomainList
    )

    # If no domain list, attempt in current context
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
    <#
    .SYNOPSIS
        Enumerates members of a resolved group using a known-good server hint.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADGroup]$Group,

        [Parameter(Mandatory=$true)]
        [string[]]$DomainList
    )

    # Prefer DN-derived domain for the group itself
    $groupDomain = $null
    if ($Group.DistinguishedName) {
        $groupDomain = Get-DomainFromDistinguishedName -DistinguishedName $Group.DistinguishedName
    }

    $tryList = New-Object System.Collections.Generic.List[string]
    if ($groupDomain) { [void]$tryList.Add($groupDomain) }
    foreach ($d in $DomainList) {
        if (-not $tryList.Contains($d)) { [void]$tryList.Add($d) }
    }

    # If no domains to try, current context
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
    <#
    .SYNOPSIS
        Converts objects into TSV text.
    .DESCRIPTION
        Outputs header + rows. Fields containing tab/newline/quote are quoted and quotes are doubled.
    #>
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

# Determine whether structured output is needed
$needsStructured = $false
if ($Name -or $Email -or ($Attributes.Count -gt 0) -or $Csv -or $Tsv) { $needsStructured = $true }

# Build output property list
$baseOutProps = @('SamAccountName')
if ($Name)  { $baseOutProps += 'Name' }
if ($Email) { $baseOutProps += 'Email' }

# Normalize additional attributes: unique, non-empty, exclude ones we already map
$extraOutProps = @()
if ($Attributes) {
    $extraOutProps = $Attributes |
        Where-Object { $_ -and $_.Trim().Length -gt 0 } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique |
        Where-Object { $_ -notin @('SamAccountName','Name','Email','mail') }
}

$outProps = @($baseOutProps + $extraOutProps)

# Determine AD properties to request
$adProps = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
[void]$adProps.Add('SamAccountName')
if ($Name)  { [void]$adProps.Add('Name') }
if ($Email) { [void]$adProps.Add('mail') }
foreach ($p in $extraOutProps) { [void]$adProps.Add($p) }

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

# Filter to users + resolve each to an AD user for property retrieval
$results = New-Object System.Collections.Generic.List[object]

foreach ($m in $members) {
    if ($m.objectClass -ne 'user') { continue }

    $u = $null
    if ($m.DistinguishedName) {
        $u = Get-ADUserCrossDomain -DistinguishedName $m.DistinguishedName -Properties ([string[]]$adProps) -FallbackDomains $fallbackDomains
    }

    if (-not $u) {
        continue
    }

    if (-not $needsStructured) {
        [void]$results.Add([pscustomobject]@{ SamAccountName = $u.SamAccountName })
        continue
    }

    $row = [ordered]@{
        SamAccountName = $u.SamAccountName
    }

    if ($Name)  { $row['Name']  = $u.Name }
    if ($Email) { $row['Email'] = $u.mail }

    foreach ($p in $extraOutProps) {
        $row[$p] = $u.$p
    }

    [void]$results.Add([pscustomobject]$row)
}

# Sort + unique by SamAccountName
$sorted = $results | Sort-Object -Property SamAccountName -Unique

if (-not $needsStructured -and -not $Csv -and -not $Tsv) {
    $sorted | ForEach-Object { $_.SamAccountName }
    exit 0
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
