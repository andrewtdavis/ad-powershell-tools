<#
.SYNOPSIS
  Compare members of two AD groups and list mismatches.

.DESCRIPTION
  Dot-sources Get-ActiveGroupMembers.ps1 (assumes it lives in the same folder).
  Compares GroupA to GroupB and outputs:
    - Members in A but not in B
    - Members in B but not in A

.PARAMETER GroupA
  Name (sAMAccountName or display name) of the first group (left / reference).

.PARAMETER GroupB
  Name (sAMAccountName or display name) of the second group (right / difference).

.PARAMETER KeyField
  Attribute used to identify matching accounts. Default: SamAccountName.

.PARAMETER Fields
  Comma-separated list of fields to return from Get-ActiveGroupMembers (default: SamAccountName,Name,Email).

.PARAMETER IncludeDisabled
  Switch to include disabled accounts when getting members.

.PARAMETER IncludeExpired
  Switch to include expired accounts when getting members.

.PARAMETER CsvOut
  Path to output CSV file (optional). If provided will write both lists to CSVs:
    <CsvOut>.A-not-in-B.csv and <CsvOut>.B-not-in-A.csv

.EXAMPLE
  .\Compare-ActiveGroupMembers.ps1 -GroupA "Domain Users" -GroupB "HR Group"

.EXAMPLE (export)
  .\Compare-ActiveGroupMembers.ps1 -GroupA "GroupA" -GroupB "GroupB" -CsvOut "C:\temp\group-diff"

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$GroupA,

    [Parameter(Mandatory=$true, Position=1)]
    [string]$GroupB,

    [Parameter(Mandatory=$false)]
    [string]$KeyField = 'SamAccountName',

    [Parameter(Mandatory=$false)]
    [string[]]$Fields = @('SamAccountName','Name','Email'),

    [switch]$IncludeDisabled,
    [switch]$IncludeExpired,

    [Parameter(Mandatory=$false)]
    [string]$CsvOut
)

try {
    # dot-source Get-ActiveGroupMembers.ps1 from same directory as this script
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
    $helper = Join-Path $scriptDir 'Get-ActiveGroupMembers.ps1'
    if (-not (Test-Path $helper)) {
        throw "Helper script not found: $helper. Place Get-ActiveGroupMembers.ps1 in the same folder as this script."
    }
    . $helper
} catch {
    Write-Error "Failed to load helper script: $_"
    exit 2
}

# Helper function to call Get-ActiveGroupMembers with switches
function Get-Members {
    param(
        [string]$GroupName
    )

    # Build splatted args
    $splat = @{
        GroupName = $GroupName
        Fields    = $Fields
    }
    if ($IncludeDisabled) { $splat.IncludeDisabled = $true }
    if ($IncludeExpired)  { $splat.IncludeExpired  = $true }

    # Call helper - if helper expects different parameter names, adjust accordingly.
    $members = & Get-ActiveGroupMembers @splat 2>$null

    if (-not $members) {
        Write-Warning "No members returned for group '$GroupName' or Get-ActiveGroupMembers failed."
        return @()
    }

    # Ensure KeyField exists on each object; fall back to using Name or DistinguishedName if missing
    foreach ($m in $members) {
        if (-not $m.PSObject.Properties.Match($KeyField)) {
            # try common fallbacks
            if ($m.PSObject.Properties.Match('SamAccountName')) {
                $m | Add-Member -NotePropertyName $KeyField -NotePropertyValue $m.SamAccountName -Force
            } elseif ($m.PSObject.Properties.Match('UserPrincipalName')) {
                $m | Add-Member -NotePropertyName $KeyField -NotePropertyValue $m.UserPrincipalName -Force
            } elseif ($m.PSObject.Properties.Match('Name')) {
                $m | Add-Member -NotePropertyName $KeyField -NotePropertyValue $m.Name -Force
            } else {
                # give it something
                $m | Add-Member -NotePropertyName $KeyField -NotePropertyValue $null -Force
            }
        }
    }

    return $members
}

Write-Verbose "Getting members for GroupA: $GroupA"
$membersA = Get-Members -GroupName $GroupA
Write-Verbose "Got $($membersA.Count) members for GroupA"

Write-Verbose "Getting members for GroupB: $GroupB"
$membersB = Get-Members -GroupName $GroupB
Write-Verbose "Got $($membersB.Count) members for GroupB"

# Normalize key values to string and uppercase for consistent comparison
function NormalizeKey {
    param($obj)
    $v = $null
    if ($null -ne $obj) {
        $prop = $obj.PSObject.Properties[$KeyField]
        if ($prop) { $v = $prop.Value }
    }
    if ($v -eq $null) { return $null }
    return [string]$v
}

# Build simple lists of keys for Compare-Object
$keysA = $membersA | ForEach-Object {
    $k = NormalizeKey $_
    # return object that keeps original properties but ensures KeyField exists and normalized
    [PSCustomObject]@{ __Key = if ($k) { $k.ToUpper() } else { $null }; __Obj = $_ }
}

$keysB = $membersB | ForEach-Object {
    $k = NormalizeKey $_
    [PSCustomObject]@{ __Key = if ($k) { $k.ToUpper() } else { $null }; __Obj = $_ }
}

# Create maps keyed by key for easy lookup (last one wins if duplicates)
$mapA = @{}
foreach ($item in $keysA) {
    $mapA[$item.__Key] = $item.__Obj
}
$mapB = @{}
foreach ($item in $keysB) {
    $mapB[$item.__Key] = $item.__Obj
}

# Use Compare-Object on key arrays (exclude null keys)
$refKeys = $mapA.Keys | Where-Object { $_ -ne $null } | Sort-Object
$diffKeys = $mapB.Keys | Where-Object { $_ -ne $null } | Sort-Object

$cmp = Compare-Object -ReferenceObject $refKeys -DifferenceObject $diffKeys -PassThru

# Split results
$inA_NotInB = @()
$inB_NotInA = @()

foreach ($k in $cmp) {
    if ($k -is [System.Management.Automation.PSObject]) { $kd = $k } # it's just a string
    # Compare-Object with -PassThru returns the differing item value (string)
    # Determine side by checking membership in each map:
    if ($mapA.ContainsKey($k) -and -not $mapB.ContainsKey($k)) {
        $inA_NotInB += $mapA[$k]
    } elseif ($mapB.ContainsKey($k) -and -not $mapA.ContainsKey($k)) {
        $inB_NotInA += $mapB[$k]
    } else {
        # shouldn't happen but ignore
    }
}

# Output results
Write-Host "--------------------------------------------------"
Write-Host "Members in '$GroupA' but NOT in '$GroupB': ($($inA_NotInB.Count))"
if ($inA_NotInB.Count -gt 0) {
    $inA_NotInB | Select-Object -Property $Fields | Format-Table -AutoSize
} else {
    Write-Host "  <none>"
}

Write-Host ""
Write-Host "Members in '$GroupB' but NOT in '$GroupA': ($($inB_NotInA.Count))"
if ($inB_NotInA.Count -gt 0) {
    $inB_NotInA | Select-Object -Property $Fields | Format-Table -AutoSize
} else {
    Write-Host "  <none>"
}
Write-Host "--------------------------------------------------"

# Optional CSV export
if ($CsvOut) {
    $dir = Split-Path -Parent $CsvOut
    if (-not [string]::IsNullOrEmpty($dir) -and -not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    $fileA = "$CsvOut.A-not-in-B.csv"
    $fileB = "$CsvOut.B-not-in-A.csv"

    $inA_NotInB | Select-Object -Property $Fields | Export-Csv -Path $fileA -NoTypeInformation -Encoding UTF8
    $inB_NotInA | Select-Object -Property $Fields | Export-Csv -Path $fileB -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "CSV exported:"
    Write-Host "  $fileA"
    Write-Host "  $fileB"
}