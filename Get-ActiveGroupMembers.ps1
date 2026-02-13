<#
.INFO
  Synopsis:
    Enumerate AD group members across domains/forests and output selected user fields.

  Description:
    Retrieves group members for the specified group (by name or distinguished name) and resolves
    each member to an AD user. Cross-domain lookups are supported by probing the member's DN-derived
    DNS domain first, then falling back to a domain list.

    Domain list behavior:
      - If -Domains is provided, it is used for group resolution and as fallback for user resolution.
      - If -Domains is not provided, the script attempts to discover domains from the current forest
        (Get-ADForest).Domains. If discovery fails, current domain context is used.

    Output formats:
      - Default: one username per line (SamAccountName), sorted unique
      - Structured: PowerShell table output if fields beyond SamAccountName are requested
      - -Csv: CSV output
      - -Tsv: TSV output (with quoting for fields that contain tabs/newlines/quotes)

    Field selection:
      - If -Fields is provided, it defines the output columns and which AD attributes are requested.
        Special aliases:
          * Email -> AD attribute mail, output column name Email
      - If -Fields is not provided, output is built from:
          SamAccountName (always), optional -Name, optional -Email, plus -Attributes.

  Parameters:
    -GroupName
      Group name (sAMAccountName, CN, or distinguished name). Supports positional usage.

    -Domains
      One or more domains or domain controllers to query.

    -Fields
      Optional. Explicit output columns / lookup fields.
      Examples: SamAccountName,Name,Email,uidNumber,employeeID

    -Name
      Include the AD 'Name' field (legacy behavior).

    -Email
      Include the AD 'mail' attribute, output column name 'Email' (legacy behavior).

    -Attributes
      Additional AD attributes to include (legacy behavior).

    -Csv
      Output structured results as CSV. Mutually exclusive with -Tsv.

    -Tsv
      Output structured results as TSV. Mutually exclusive with -Csv.

  Examples:
    # Default output: usernames only
    .\Get-ActiveGroupMembers.ps1 "CoreHPC_Base"

    # Legacy behavior
    .\Get-ActiveGroupMembers.ps1 "CoreHPC_Base" -Name -Email -Attributes EmployeeID,LastLogonDate

    # Explicit fields (drives lookup + output)
    .\Get-ActiveGroupMembers.ps1 "CoreHPC_Base" -Fields SamAccountName,Name,Email,uidNumber -Tsv

    # CSV with explicit fields
    .\Get-ActiveGroupMembers.ps1 "CoreHPC_Base" -Fields SamAccountName,Email,Department -Csv
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

function Normalize-UniqueNonEmpty {
    param([string[]]$Values)
    if (-not $Values) { return @() }
    $Values |
        Where-Object { $_ -and $_.Trim().Length -gt 0 } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique
}

function Build-FieldPlan {
    <#
    .SYNOPSIS
        Builds output column plan and AD property request list.
    .DESCRIPTION
        Returns:
          - OutColumns: ordered list of output column names
          - AdProps: AD properties to request via Get-ADUser
          - ColumnToAdProp: mapping output column -> AD property name
    #>
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

# Determine whether structured output is needed
$needsStructured = $false

# Explicit fields means structured unless it is only SamAccountName and no forced formatting.
if ($fieldPlan.UsesExplicit) {
    if ($outProps.Count -gt 1) { $needsStructured = $true }
} else {
    if ($Name -or $Email -or ($Attributes.Count -gt 0)) { $needsStructured = $true }
}

if ($Csv -or $Tsv) { $needsStructured = $true }

# If still not structured, output usernames only
if (-not $needsStructured) {
    $namesOnly = New-Object System.Collections.Generic.List[string]
    foreach ($m in $members) {
        if ($m.objectClass -ne 'user') { continue }
        if ($m.SamAccountName) { [void]$namesOnly.Add([string]$m.SamAccountName) }
    }
    $namesOnly | Sort-Object -Unique
    exit 0
}

# Resolve each member to an AD user for property retrieval and build output rows
$results = New-Object System.Collections.Generic.List[object]

foreach ($m in $members) {
    if ($m.objectClass -ne 'user') { continue }

    $u = $null
    if ($m.DistinguishedName) {
        $u = Get-ADUserCrossDomain -DistinguishedName $m.DistinguishedName -Properties $adProps -FallbackDomains $fallbackDomains
    }

    if (-not $u) {
        continue
    }

    $row = [ordered]@{}
    foreach ($col in $outProps) {
        $adProp = $colToProp[$col]
        $row[$col] = $u.$adProp
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