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

# Resolve a group string to an identity and server (same Resolve-Group as before)
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

# Core: call helper either as function or as script file with splatting
function Invoke-Helper {
    param(
        [hashtable]$SplatArgs
    )

    # Clean empty entries (avoid passing $null members)
    $clean = @{}
    foreach ($k in $SplatArgs.Keys) {
        if ($SplatArgs[$k] -ne $null) { $clean[$k] = $SplatArgs[$k] }
    }

    # If a function named Get-ActiveGroupMembers exists, call it; otherwise call the script file path
    $isFunction = $false
    try {
        $cmd = Get-Command -Name Get-ActiveGroupMembers -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.CommandType -eq 'Function') { $isFunction = $true }
    } catch { $isFunction = $false }

    if ($isFunction) {
        Write-DebugLine "Invoking function Get-ActiveGroupMembers with splatted args."
        return & Get-ActiveGroupMembers @clean
    } else {
        # Call script by full path. Use -File invocation to avoid param name auto-resolution issues.
        # PowerShell does not accept splatting on script with & when the script is not a function; instead run powershell -File is not desired.
        # But calling & $helperPath @clean works in practice - ensure $helperPath is full path.
        Write-DebugLine "Invoking script file $helperPath with splatted args."
        return & $helperPath @clean
    }
}

# Get members wrapper that prepares the correct parameter name for helper
function Get-Members {
    param(
        [string]$ResolvedIdentity,
        [string]$Server,
        [switch]$IsDistinguishedName
    )

    # Build candidate splat with common param names - helper may accept any of these:
    $candidateSplats = @()

    # 1) GroupName (most common in earlier helper)
    $candidateSplats += @{ GroupName = $ResolvedIdentity; Fields = $Fields; Server = $Server }

    # 2) Identity
    $candidateSplats += @{ Identity = $ResolvedIdentity; Fields = $Fields; Server = $Server }

    # 3) DistinguishedName (if DN)
    $candidateSplats += @{ DistinguishedName = $ResolvedIdentity; Fields = $Fields; Server = $Server }

    # 4) Fallback raw positional (some scripts expect first positional param)
    $candidateSplats += @{ $null = $ResolvedIdentity }  # not used for splatting - will not work, kept for illustration

    # Try each candidate splat until one returns non-empty without prompting
    foreach ($s in $candidateSplats) {
        # Skip any hashtable with null key entries
        $splat = @{}
        foreach ($k in $s.Keys) {
            if ($k -eq $null) { continue }
            if ($s[$k] -ne $null) { $splat[$k] = $s[$k] }
        }

        # Forward switches if present and helper supports them (Invoke-Helper will pass them; helper may ignore unknown params)
        if ($IncludeDisabled) { $splat['IncludeDisabled'] = $true }
        if ($IncludeExpired) { $splat['IncludeExpired'] = $true }

        Write-DebugLine ("Trying helper with parameters: {0}" -f ($splat | Out-String))

        # Invoke helper
        $result = Invoke-Helper -SplatArgs $splat 2>&1

        # If result is empty array or $null, try next; if it returned an ErrorRecord or string prompting, handle carefully
        if ($result -is [System.Management.Automation.ErrorRecord]) {
            Write-DebugLine "Helper returned an ErrorRecord; trying next parameter form."
            continue
        }

        # If result contains a prompt text like 'Supply values for the following parameters', treat as failure
        $asString = $null
        try { $asString = $result | Out-String } catch { $asString = $null }

        if ($asString -and $asString -match 'Supply values for the following parameters') {
            Write-DebugLine "Helper appears to have prompted; trying next parameter form."
            continue
        }

        # Successful-ish result
        return ,$result
    }

    # Last attempt: call the script passing the identity positionally using & $helperPath - will still prompt if helper needs named params
    try {
        Write-DebugLine "Last attempt: calling helper script path with positional argument."
        $posResult = & $helperPath $ResolvedIdentity
        return ,$posResult
    } catch {
        Write-Warning "Final attempt failed: $($_.Exception.Message)"
        return @()
    }
}

# Compute prefer-server values
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

# Fetch members using robust caller
$membersA = Get-Members -ResolvedIdentity $resolveA.Identity -Server $resolveA.Server -IsDistinguishedName:($resolveA.IdentityType -match 'DN|ResolvedDN')
$membersB = Get-Members -ResolvedIdentity $resolveB.Identity -Server $resolveB.Server -IsDistinguishedName:($resolveB.IdentityType -match 'DN|ResolvedDN')

if (($membersA.Count -eq 0) -and ($membersB.Count -eq 0)) {
    Write-Error "No members returned for either group. Verify connectivity, credentials, and helper parameter expectations."
    exit 3
}

# Normalize and diff (same approach as before)
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
    $keyn = if ($k) { $k.ToUpper() } else { [Guid]::NewGuid().ToString() }
    $mapA[$keyn] = $m
}
$mapB = @{}
foreach ($m in ,$membersB) {
    $k = NormalizeKey $m
    $keyn = if ($k) { $k.ToUpper() } else { [Guid]::NewGuid().ToString() }
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

# Output and CSV (unchanged)
Write-Host "--------------------------------------------------"
Write-Host ("Members in '{0}' (resolved: {1}) but NOT in '{2}' (resolved: {3}): ({4})" -f $GroupA, $resolveA.Identity, $GroupB, $resolveB.Identity, $inA_NotInB.Count)
if ($inA_NotInB.Count -gt 0) { $inA_NotInB | Select-Object -Property $Fields | Format-Table -AutoSize } else { Write-Host "  <none>" }

Write-Host ""
Write-Host ("Members in '{0}' (resolved: {1}) but NOT in '{2}' (resolved: {3}): ({4})" -f $GroupB, $resolveB.Identity, $GroupA, $resolveA.Identity, $inB_NotInA.Count)
if ($inB_NotInA.Count -gt 0) { $inB_NotInA | Select-Object -Property $Fields | Format-Table -AutoSize } else { Write-Host "  <none>" }
Write-Host "--------------------------------------------------"

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