<#
.SYNOPSIS
  Compare members of two AD groups across domains with automatic domain inference.

.DESCRIPTION
  Robustly calls Get-ActiveGroupMembers either as a function (if defined) or the script file by path,
  passing resolved identities via splatting to avoid interactive prompts.

NOTES
  - Save this in the same folder as Get-ActiveGroupMembers.ps1.
  - Requires ActiveDirectory RSAT for Get-ADGroup lookups (optional).
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

# Locate helper script path
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$helperPath = Join-Path $scriptDir 'Get-ActiveGroupMembers.ps1'
if (-not (Test-Path $helperPath)) {
    Write-Error "Helper script not found: $helperPath. Place Get-ActiveGroupMembers.ps1 in the same folder."
    exit 2
}

function Write-DebugLine {
    param($Message)
    if ($PSBoundParameters.ContainsKey('Verbose') -or $VerbosePreference -ne 'SilentlyContinue') {
        Write-Verbose $Message
    }
}

# Resolve a group string to an identity and server
function Resolve-Group {
    param(
        [string]$GroupInput,
        [string]$PreferServer
    )

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

    # Try AD cmdlets if available
    $adAvailable = $false
    try {
        if (Get-Command -Name Get-ADGroup -ErrorAction Stop) { $adAvailable = $true }
    } catch { $adAvailable = $false }

    if ($adAvailable) {
        try {
            Write-DebugLine "Attempting Get-ADGroup -Identity '$GroupInput' (no server)..."
            $g = Get-ADGroup -Identity $GroupInput -ErrorAction Stop
            return @{ Identity = $g.DistinguishedName; Server = $g.DNSHostName; IdentityType = 'ResolvedDN' }
        } catch {
            Write-DebugLine "Local lookup failed for '$GroupInput': $($_.Exception.Message)"
        }

        if ($PreferServer) {
            try {
                Write-DebugLine "Attempting Get-ADGroup -Identity '$GroupInput' -Server '$PreferServer'..."
                $g2 = Get-ADGroup -Identity $GroupInput -Server $PreferServer -ErrorAction Stop
                return @{ Identity = $g2.DistinguishedName; Server = $PreferServer; IdentityType = 'ResolvedDN' }
            } catch {
                Write-DebugLine "Lookup at server '$PreferServer' failed: $($_.Exception.Message)"
            }
        }

        if ($UseGlobalCatalog) {
            try {
                $gcHost = $null
                $gcdcs = Get-ADDomainController -Filter {IsGlobalCatalog -eq $true} -ErrorAction SilentlyContinue
                if ($gcdcs) { $gcHost = ($gcdcs | Select-Object -First 1).HostName + ':3268' }

                if (-not $gcHost) {
                    if ($Domain) { $gcHost = "$Domain:3268" }
                    elseif ($PreferServer) { $gcHost = "$PreferServer:3268" }
                }
                if ($gcHost) {
                    Write-DebugLine "Attempting GC lookup on $gcHost..."
                    $g3 = Get-ADGroup -Identity $GroupInput -Server $gcHost -ErrorAction Stop
                    return @{ Identity = $g3.DistinguishedName; Server = $gcHost; IdentityType = 'ResolvedDN' }
                }
            } catch {
                Write-DebugLine "GC lookup failed: $($_.Exception.Message)"
            }
        }

        $candidates = @()
        if ($PreferServer) { $candidates += $PreferServer }
        if ($Domain) { $candidates += $Domain }
        foreach ($cand in $candidates | Where-Object { $_ }) {
            try {
                Write-DebugLine "Attempting Get-ADGroup -Identity '$GroupInput' -Server '$cand'..."
                $g4 = Get-ADGroup -Identity $GroupInput -Server $cand -ErrorAction Stop
                return @{ Identity = $g4.DistinguishedName; Server = $cand; IdentityType = 'ResolvedDN' }
            } catch {
                Write-DebugLine "Candidate server lookup failed: $($_.Exception.Message)"
            }
        }
    } else {
        Write-DebugLine "ActiveDirectory module not available; skipping Get-ADGroup lookups."
    }

    return @{ Identity = $GroupInput; Server = $PreferServer; IdentityType = 'Unresolved' }
}

# Invoke helper as function or script file
function Invoke-Helper {
    param(
        [hashtable]$SplatArgs
    )

    # Clean empty entries
    $clean = @{}
    foreach ($k in $SplatArgs.Keys) {
        if ($SplatArgs[$k] -ne $null) { $clean[$k] = $SplatArgs[$k] }
    }

    # Detect function
    $isFunction = $false
    try {
        $cmd = Get-Command -Name Get-ActiveGroupMembers -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.CommandType -eq 'Function') { $isFunction = $true }
    } catch { $isFunction = $false }

    if ($isFunction) {
        Write-DebugLine "Invoking function Get-ActiveGroupMembers with splatted args."
        return & Get-ActiveGroupMembers @clean
    } else {
        Write-DebugLine "Invoking script file $helperPath with splatted args."
        return & $helperPath @clean
    }
}

# Build and try several splat forms, then fallback to positional call
function Get-Members {
    param(
        [string]$ResolvedIdentity,
        [string]$Server,
        [switch]$IsDistinguishedName
    )

    # Candidate splats with common parameter names
    $candidateSplats = @()

    $candidateSplats += @{ GroupName = $ResolvedIdentity; Fields = $Fields; Server = $Server }
    $candidateSplats += @{ Identity = $ResolvedIdentity; Fields = $Fields; Server = $Server }
    $candidateSplats += @{ DistinguishedName = $ResolvedIdentity; Fields = $Fields; Server = $Server }

    foreach ($splat in $candidateSplats) {
        # Forward switches if present
        if ($IncludeDisabled) { $splat['IncludeDisabled'] = $true }
        if ($IncludeExpired) { $splat['IncludeExpired'] = $true }

        # Remove null values
        $clean = @{}
        foreach ($k in $splat.Keys) {
            if ($splat[$k] -ne $null) { $clean[$k] = $splat[$k] }
        }

        Write-DebugLine ("Trying helper with parameters: {0}" -f ($clean | Out-String))

        try {
            $result = Invoke-Helper -SplatArgs $clean 2>&1
        } catch {
            Write-DebugLine "Invoke-Helper threw: $($_.Exception.Message)"
            $result = $null
        }

        if ($result -eq $null) { continue }

        # Convert to string to detect prompt text
        $asString = $null
        try { $asString = $result | Out-String } catch { $asString = $null }

        if ($asString -and $asString -match 'Supply values for the following parameters') {
            Write-DebugLine "Helper appears to have prompted; trying next parameter form."
            continue
        }

        # Otherwise return whatever was returned (could be empty array)
        return ,$result
    }

    # Final fallback: call script with positional arg (may still prompt if helper requires named params)
    try {
        Write-DebugLine "Final fallback: calling script path with positional identity."
        $posResult = & $helperPath $ResolvedIdentity
        return ,$posResult
    } catch {
        Write-Warning "Final fallback failed: $($_.Exception.Message)"
        return @()
    }
}

# Compute prefer-server
$preferA = $null
if ($DomainA) { $preferA = $DomainA } elseif ($Domain) { $preferA = $Domain }

$preferB = $null
if ($DomainB) { $preferB = $DomainB } elseif ($Domain) { $preferB = $Domain }

# Resolve groups
$resolveA = Resolve-Group -GroupInput $GroupA -PreferServer $preferA
$resolveB = Resolve-Group -GroupInput $GroupB -PreferServer $preferB

Write-Host ("Resolved GroupA: Identity = {0}  Server = {1}  Type = {2}" -f $resolveA.Identity, $resolveA.Server, $resolveA.IdentityType)
Write-Host ("Resolved GroupB: Identity = {0}  Server = {1}  Type = {2}" -f $resolveB.Identity, $resolveB.Server, $resolveB.IdentityType)

if ($AutoResolve -and ($resolveA.IdentityType -eq 'Unresolved' -or $resolveB.IdentityType -eq 'Unresolved')) {
    Write-Warning "One or both groups could not be conclusively resolved. The script will still attempt to call the helper with the best available values."
}

# Fetch members
$membersA = Get-Members -ResolvedIdentity $resolveA.Identity -Server $resolveA.Server -IsDistinguishedName:($resolveA.IdentityType -match 'DN|ResolvedDN')
$membersB = Get-Members -ResolvedIdentity $resolveB.Identity -Server $resolveB.Server -IsDistinguishedName:($resolveB.IdentityType -match 'DN|ResolvedDN')

if (($membersA.Count -eq 0) -and ($membersB.Count -eq 0)) {
    Write-Error "No members returned for either group. Verify connectivity, credentials, and helper parameter expectations."
    exit 3
}

# Normalize KeyField and compute diffs
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

$mapA = @{}
foreach ($m in ,$membersA) {
    $k = NormalizeKey $m
    if ($k) { $keyn = $k.ToUpper() } else { $keyn = [Guid]::NewGuid().ToString() }
    $mapA[$keyn] = $m
}
$mapB = @{}
foreach ($m in ,$membersB) {
    $k = NormalizeKey $m
    if ($k) { $keyn = $k.ToUpper() } else { $keyn = [Guid]::NewGuid().ToString() }
    $mapB[$keyn] = $m
}

$refKeys = $mapA.Keys | Sort-Object
$diffKeys = $mapB.Keys | Sort-Object

$cmp = Compare-Object -ReferenceObject $refKeys -DifferenceObject $diffKeys -PassThru

$inA_NotInB = @()
$inB_NotInA = @()

foreach ($k in $cmp) {
    if ($mapA.ContainsKey($k) -and -not $mapB.ContainsKey($k)) { $inA_NotInB += $mapA[$k] }
    elseif ($mapB.ContainsKey($k) -and -not $mapA.ContainsKey($k)) { $inB_NotInA += $mapB[$k] }
}

# Output
Write-Host "--------------------------------------------------"
Write-Host ("Members in '{0}' (resolved: {1}) but NOT in '{2}' (resolved: {3}): ({4})" -f $GroupA, $resolveA.Identity, $GroupB, $resolveB.Identity, $inA_NotInB.Count)
if ($inA_NotInB.Count -gt 0) { $inA_NotInB | Select-Object -Property $Fields | Format-Table -AutoSize } else { Write-Host "  <none>" }

Write-Host ""
Write-Host ("Members in '{0}' (resolved: {1}) but NOT in '{2}' (resolved: {3}): ({4})" -f $GroupB, $resolveB.Identity, $GroupA, $resolveA.Identity, $inB_NotInA.Count)
if ($inB_NotInA.Count -gt 0) { $inB_NotInA | Select-Object -Property $Fields | Format-Table -AutoSize } else { Write-Host "  <none>" }
Write-Host "--------------------------------------------------"

# CSV export
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