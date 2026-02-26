<#
.SYNOPSIS
  Compare members of two AD groups across domains with automatic domain inference.

.DESCRIPTION
  - Invokes Get-ActiveGroupMembers.ps1 (helper must be in same folder).
  - Attempts to infer domain/server for each group; supports -DomainA/-DomainB or -Domain (single).
  - Exits if either group cannot be resolved (no fallbacks).
  - Filters out completely-empty member objects before formatting output.
  - Prints a clear message if memberships are identical.

.NOTES
  - PowerShell 5.1 compatible.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$GroupA,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$GroupB,

    [string]$DomainA,
    [string]$DomainB,
    [string]$Domain,

    [switch]$UseGlobalCatalog,

    [switch]$AutoResolve = $true,

    [switch]$IncludeDisabled,
    [switch]$IncludeExpired,

    [string]$KeyField = 'SamAccountName',
    [string[]]$Fields = @('SamAccountName','Name','Email'),

    [string]$CsvOut
)

# Helper script path (must exist)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$helperPath = Join-Path $scriptDir 'Get-ActiveGroupMembers.ps1'
if (-not (Test-Path $helperPath)) {
    Write-Error "Helper script not found: $helperPath. Place Get-ActiveGroupMembers.ps1 in the same folder."
    exit 2
}

function Write-DebugLine { param($M) if ($PSBoundParameters.ContainsKey('Verbose') -or $VerbosePreference -ne 'SilentlyContinue') { Write-Verbose $M } }

# Resolve a group string to an identity and server
function Resolve-Group {
    param([string]$GroupInput,[string]$PreferServer)

    # Recognize obvious formats first
    if ($GroupInput -match '^CN=.*DC=.*' -or $GroupInput -match '^OU=.*DC=.*') {
        return @{ Identity = $GroupInput; Server = $null; IdentityType = 'DN' }
    }
    if ($GroupInput -match '^[^\\]+\\.+') {
        $parts = $GroupInput.Split('\',2)
        return @{ Identity = $parts[1]; Server = $parts[0]; IdentityType = 'SAM_WITH_DOMAIN' }
    }
    if ($GroupInput -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        return @{ Identity = $GroupInput; Server = $null; IdentityType = 'GUID' }
    }
    if ($GroupInput -match '^S-\d-\d+-.+') {
        return @{ Identity = $GroupInput; Server = $null; IdentityType = 'SID' }
    }
    if ($GroupInput -match '@') {
        return @{ Identity = $GroupInput; Server = $null; IdentityType = 'UPN' }
    }

    if (-not $AutoResolve) {
        return @{ Identity = $GroupInput; Server = $PreferServer; IdentityType = 'Raw' }
    }

    # Try AD cmdlets (Get-ADGroup) if available
    $adAvailable = $false
    try { if (Get-Command -Name Get-ADGroup -ErrorAction Stop) { $adAvailable = $true } } catch { $adAvailable = $false }

    if ($adAvailable) {
        try {
            Write-DebugLine "Attempting Get-ADGroup -Identity '$GroupInput' (no server)..."
            $g = Get-ADGroup -Identity $GroupInput -ErrorAction Stop
            return @{ Identity = $g.DistinguishedName; Server = $g.DNSHostName; IdentityType = 'ResolvedDN' }
        } catch { Write-DebugLine "Local lookup failed: $($_.Exception.Message)" }

        if ($PreferServer) {
            try {
                Write-DebugLine "Attempting Get-ADGroup -Identity '$GroupInput' -Server '$PreferServer'..."
                $g2 = Get-ADGroup -Identity $GroupInput -Server $PreferServer -ErrorAction Stop
                return @{ Identity = $g2.DistinguishedName; Server = $PreferServer; IdentityType = 'ResolvedDN' }
            } catch { Write-DebugLine "Prefer-server lookup failed: $($_.Exception.Message)" }
        }

        if ($UseGlobalCatalog) {
            try {
                $gcdcs = Get-ADDomainController -Filter {IsGlobalCatalog -eq $true} -ErrorAction SilentlyContinue
                $gcHost = $null
                if ($gcdcs) { $gcHost = ($gcdcs | Select-Object -First 1).HostName + ':3268' }
                if (-not $gcHost) {
                    if ($Domain) { $gcHost = "$Domain:3268" } elseif ($PreferServer) { $gcHost = "$PreferServer:3268" }
                }
                if ($gcHost) {
                    Write-DebugLine "Attempting GC lookup on $gcHost..."
                    $g3 = Get-ADGroup -Identity $GroupInput -Server $gcHost -ErrorAction Stop
                    return @{ Identity = $g3.DistinguishedName; Server = $gcHost; IdentityType = 'ResolvedDN' }
                }
            } catch { Write-DebugLine "GC lookup failed: $($_.Exception.Message)" }
        }

        $candidates = @()
        if ($PreferServer) { $candidates += $PreferServer }
        if ($Domain) { $candidates += $Domain }
        foreach ($cand in $candidates | Where-Object { $_ }) {
            try {
                Write-DebugLine "Attempting Get-ADGroup -Identity '$GroupInput' -Server '$cand'..."
                $g4 = Get-ADGroup -Identity $GroupInput -Server $cand -ErrorAction Stop
                return @{ Identity = $g4.DistinguishedName; Server = $cand; IdentityType = 'ResolvedDN' }
            } catch { Write-DebugLine "Candidate lookup failed: $($_.Exception.Message)" }
        }
    } else {
        Write-DebugLine "ActiveDirectory module not present; skipping AD lookups."
    }

    # Unresolved
    return @{ Identity = $GroupInput; Server = $PreferServer; IdentityType = 'Unresolved' }
}

# Invoke helper either as function or script file
function Invoke-Helper {
    param([hashtable]$SplatArgs)
    $clean = @{}
    foreach ($k in $SplatArgs.Keys) { if ($SplatArgs[$k] -ne $null) { $clean[$k] = $SplatArgs[$k] } }

    $isFunction = $false
    try {
        $cmd = Get-Command -Name Get-ActiveGroupMembers -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.CommandType -eq 'Function') { $isFunction = $true }
    } catch {}

    if ($isFunction) {
        Write-DebugLine "Invoking function Get-ActiveGroupMembers"
        return & Get-ActiveGroupMembers @clean
    } else {
        Write-DebugLine "Invoking script file $helperPath"
        return & $helperPath @clean
    }
}

# Try common param names; final fallback is positional script call
function Get-Members {
    param([string]$ResolvedIdentity,[string]$Server,[switch]$IsDistinguishedName)

    $candidateSplats = @()
    $candidateSplats += @{ GroupName = $ResolvedIdentity; Fields = $Fields; Server = $Server }
    $candidateSplats += @{ Identity = $ResolvedIdentity; Fields = $Fields; Server = $Server }
    $candidateSplats += @{ DistinguishedName = $ResolvedIdentity; Fields = $Fields; Server = $Server }

    foreach ($splat in $candidateSplats) {
        if ($IncludeDisabled) { $splat['IncludeDisabled'] = $true }
        if ($IncludeExpired) { $splat['IncludeExpired'] = $true }

        $clean = @{}
        foreach ($k in $splat.Keys) { if ($splat[$k] -ne $null) { $clean[$k] = $splat[$k] } }

        Write-DebugLine ("Trying helper with: {0}" -f ($clean | Out-String))

        try { $result = Invoke-Helper -SplatArgs $clean 2>&1 } catch { Write-DebugLine "Invoke-Helper threw: $($_.Exception.Message)"; $result = $null }

        if ($result -eq $null) { continue }

        $asString = $null
        try { $asString = $result | Out-String } catch {}
        if ($asString -and $asString -match 'Supply values for the following parameters') {
            Write-DebugLine "Helper prompted - trying next param form."
            continue
        }

        return ,$result
    }

    # Final positional attempt (may prompt)
    try {
        Write-DebugLine "Final positional call to helper script path"
        $posResult = & $helperPath $ResolvedIdentity
        return ,$posResult
    } catch {
        Write-Warning "Final fallback failed: $($_.Exception.Message)"
        return @()
    }
}

# Helper: return true if object has any non-empty value in any of $Fields
function HasAnyField {
    param($obj, [string[]]$checkFields)
    foreach ($f in $checkFields) {
        if ($null -ne $obj.PSObject.Properties.Match($f)) {
            $val = $obj.PSObject.Properties[$f].Value
            if ($val -ne $null -and -not ([string]::IsNullOrWhiteSpace([string]$val))) { return $true }
        }
    }
    return $false
}

# Compute prefer-server values (PS5.1-safe)
$preferA = $null
if ($DomainA) { $preferA = $DomainA } elseif ($Domain) { $preferA = $Domain }
$preferB = $null
if ($DomainB) { $preferB = $DomainB } elseif ($Domain) { $preferB = $Domain }

# Resolve groups
$resolveA = Resolve-Group -GroupInput $GroupA -PreferServer $preferA
$resolveB = Resolve-Group -GroupInput $GroupB -PreferServer $preferB

# Tighten server display to show <none> when empty
$serverA = if ($resolveA.Server) { $resolveA.Server } else { '<none>' }
$serverB = if ($resolveB.Server) { $resolveB.Server } else { '<none>' }

Write-Host ("Resolved GroupA: Identity = {0}  Server = {1}  Type = {2}" -f $resolveA.Identity, $serverA, $resolveA.IdentityType)
Write-Host ("Resolved GroupB: Identity = {0}  Server = {1}  Type = {2}" -f $resolveB.Identity, $serverB, $resolveB.IdentityType)

# If either unresolved, exit (no fallbacks)
if ($resolveA.IdentityType -eq 'Unresolved' -or $resolveB.IdentityType -eq 'Unresolved') {
    Write-Error "One or both groups could not be resolved conclusively. Provide a domain/server, DN, or GUID/SID for the unresolved group(s). Exiting."
    exit 4
}

# Fetch member lists
$membersA = Get-Members -ResolvedIdentity $resolveA.Identity -Server $resolveA.Server -IsDistinguishedName:($resolveA.IdentityType -match 'DN|ResolvedDN')
$membersB = Get-Members -ResolvedIdentity $resolveB.Identity -Server $resolveB.Server -IsDistinguishedName:($resolveB.IdentityType -match 'DN|ResolvedDN')

# If both empty, error and exit
if (($membersA.Count -eq 0) -and ($membersB.Count -eq 0)) {
    Write-Error "No members returned for either group. Verify connectivity, credentials, and helper parameter expectations."
    exit 3
}

# Normalize KeyField and produce maps (drop members that have no useful fields for display)
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

# Build maps, skipping completely-empty member objects
$mapA = @{}
foreach ($m in ,$membersA) {
    if (-not (HasAnyField $m $Fields)) { continue }
    $k = NormalizeKey $m
    if ($k) { $keyn = $k.ToUpper() } else { $keyn = [Guid]::NewGuid().ToString() }
    $mapA[$keyn] = $m
}
$mapB = @{}
foreach ($m in ,$membersB) {
    if (-not (HasAnyField $m $Fields)) { continue }
    $k = NormalizeKey $m
    if ($k) { $keyn = $k.ToUpper() } else { $keyn = [Guid]::NewGuid().ToString() }
    $mapB[$keyn] = $m
}

# --- SAFETY: If both maps are empty after filtering, treat as identical and exit ---
if (($mapA.Count -eq 0) -and ($mapB.Count -eq 0)) {
    Write-Host "--------------------------------------------------"
    Write-Host ("Groups '{0}' and '{1}' have identical membership." -f $GroupA, $GroupB)
    Write-Host "No differences found."
    Write-Host "--------------------------------------------------"
    if ($CsvOut) {
        $dir = Split-Path -Parent $CsvOut
        if (-not [string]::IsNullOrEmpty($dir) -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        $fileA = "$CsvOut.A-not-in-B.csv"
        $fileB = "$CsvOut.B-not-in-A.csv"
        $empty = @()
        $empty | Select-Object -Property $Fields | Export-Csv -Path $fileA -NoTypeInformation -Encoding UTF8
        $empty | Select-Object -Property $Fields | Export-Csv -Path $fileB -NoTypeInformation -Encoding UTF8
        Write-Host "CSV exported (empty differences):"
        Write-Host "  $fileA"
        Write-Host "  $fileB"
    }
    exit 0
}

# Safe key extraction (wrap in array to guarantee non-null)
$refKeys = @($mapA.Keys)
$diffKeys = @($mapB.Keys)

# Compare
$cmp = Compare-Object -ReferenceObject $refKeys -DifferenceObject $diffKeys -PassThru

$inA_NotInB = @()
$inB_NotInA = @()
foreach ($k in $cmp) {
    if ($mapA.ContainsKey($k) -and -not $mapB.ContainsKey($k)) { $inA_NotInB += $mapA[$k] }
    elseif ($mapB.ContainsKey($k) -and -not $mapA.ContainsKey($k)) { $inB_NotInA += $mapB[$k] }
}

# Output with explicit identical-members message
Write-Host "--------------------------------------------------"

if (($inA_NotInB.Count -eq 0) -and ($inB_NotInA.Count -eq 0)) {
    Write-Host ("Groups '{0}' and '{1}' have identical membership." -f $GroupA, $GroupB)
    Write-Host "No differences found."
    Write-Host "--------------------------------------------------"
    if ($CsvOut) {
        $dir = Split-Path -Parent $CsvOut
        if (-not [string]::IsNullOrEmpty($dir) -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        $fileA = "$CsvOut.A-not-in-B.csv"
        $fileB = "$CsvOut.B-not-in-A.csv"
        $empty = @()
        $empty | Select-Object -Property $Fields | Export-Csv -Path $fileA -NoTypeInformation -Encoding UTF8
        $empty | Select-Object -Property $Fields | Export-Csv -Path $fileB -NoTypeInformation -Encoding UTF8
        Write-Host "CSV exported (empty differences):"
        Write-Host "  $fileA"
        Write-Host "  $fileB"
    }
    exit 0
}

# Show differences
Write-Host ("Members in '{0}' but NOT in '{1}': ({2})" -f $GroupA, $GroupB, $inA_NotInB.Count)
if ($inA_NotInB.Count -gt 0) {
    $inA_NotInB | Select-Object -Property $Fields | Format-Table -AutoSize
} else {
    Write-Host "  <none>"
}

Write-Host ""
Write-Host ("Members in '{0}' but NOT in '{1}': ({2})" -f $GroupB, $GroupA, $inB_NotInA.Count)
if ($inB_NotInA.Count -gt 0) {
    $inB_NotInA | Select-Object -Property $Fields | Format-Table -AutoSize
} else {
    Write-Host "  <none>"
}

Write-Host "--------------------------------------------------"

# CSV export for actual diffs
if ($CsvOut) {
    $dir = Split-Path -Parent $CsvOut
    if (-not [string]::IsNullOrEmpty($dir) -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    $fileA = "$CsvOut.A-not-in-B.csv"
    $fileB = "$CsvOut.B-not-in-A.csv"
    $inA_NotInB | Select-Object -Property $Fields | Export-Csv -Path $fileA -NoTypeInformation -Encoding UTF8
    $inB_NotInA | Select-Object -Property $Fields | Export-Csv -Path $fileB -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "CSV exported:"
    Write-Host "  $fileA"
    Write-Host "  $fileB"
}