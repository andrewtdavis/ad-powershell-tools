<#
.SYNOPSIS
  Compare members of two AD groups across domains with automatic domain inference.

.DESCRIPTION
  Dot-sources Get-ActiveGroupMembers.ps1 (assumes it is in the same folder).
  Attempts to infer domain/server for each group; supports -DomainA/-DomainB or -Domain (single).
  Resolves group identities before calling the helper to avoid interactive prompts.

PARAMETERS
  GroupA - First group (positional). Can be samAccountName, "DOMAIN\Group", distinguishedName, GUID, or UPN.
  GroupB - Second group (positional).
  DomainA - Optional domain or server to use for GroupA (e.g. dc1.example.com or example.com).
  DomainB - Optional domain or server to use for GroupB.
  Domain - Optional single domain/server to use for both groups.
  UseGlobalCatalog - Switch: try a Global Catalog (3268) lookup as a last resort.
  AutoResolve - Switch (default: $true): attempt resolution before calling the helper; if set to $false the raw values are passed through.
  IncludeDisabled - Switch forwarded to helper if supported.
  IncludeExpired - Switch forwarded to helper if supported.
  KeyField - Field to use for member matching (default: SamAccountName).
  Fields - Fields to show/export (default SamAccountName,Name,Email).
  CsvOut - Path prefix for CSV export.

.EXAMPLES
  PS> .\Compare-ActiveGroupMembers.ps1 CoreHPC_base CoreHPC_Tier1 -Domain contoso.example.com

  PS> .\Compare-ActiveGroupMembers.ps1 "CORP\CoreHPC_base" "OTHER\CoreHPC_Tier1"

  PS> .\Compare-ActiveGroupMembers.ps1 CoreHPC_base CoreHPC_Tier1 -DomainA dc1.corp.example.com -DomainB dc1.other.example.com -CsvOut C:\temp\groupdiff

.NOTES
  - Requires Get-ActiveGroupMembers.ps1 to expose a function named Get-ActiveGroupMembers and reside in same folder.
  - Get-AD* cmdlets require the ActiveDirectory RSAT module; the script falls back gracefully if those cmdlets are not available.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$GroupA,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$GroupB,

    [string]$DomainA,
    [string]$DomainB,
    [string]$Domain,                # removed Alias to avoid name/alias conflict

    [switch]$UseGlobalCatalog,

    [switch]$AutoResolve = $true,

    [switch]$IncludeDisabled,
    [switch]$IncludeExpired,

    [string]$KeyField = 'SamAccountName',
    [string[]]$Fields = @('SamAccountName','Name','Email'),

    [string]$CsvOut
)

# Dot-source helper
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$helper = Join-Path $scriptDir 'Get-ActiveGroupMembers.ps1'
if (-not (Test-Path $helper)) {
    Write-Error "Helper script not found: $helper. Place Get-ActiveGroupMembers.ps1 in the same folder."
    exit 2
}
. $helper

function Write-DebugLine {
    param($Message)
    # Only write when -Verbose is passed
    if ($PSBoundParameters.ContainsKey('Verbose') -or $VerbosePreference -ne 'SilentlyContinue') {
        Write-Verbose $Message
    }
}

# Resolve a group string to an identity and (optionally) a server to target.
function Resolve-Group {
    param(
        [string]$GroupInput,
        [string]$PreferServer
    )

    # Return hashtable: Identity, Server, IdentityType
    # Quick pattern checks
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

    # Attempt to use Get-ADGroup if available
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

        # Try prefer server if provided
        if ($PreferServer) {
            try {
                Write-DebugLine "Attempting Get-ADGroup -Identity '$GroupInput' -Server '$PreferServer'..."
                $g2 = Get-ADGroup -Identity $GroupInput -Server $PreferServer -ErrorAction Stop
                return @{ Identity = $g2.DistinguishedName; Server = $PreferServer; IdentityType = 'ResolvedDN' }
            } catch {
                Write-DebugLine "Lookup at server '$PreferServer' failed: $($_.Exception.Message)"
            }
        }

        # Try Global Catalog if requested
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

        # Last-ditch attempt: try candidate servers built from Domain/PreferServer
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

    # Nothing resolved: return raw with prefer server
    return @{ Identity = $GroupInput; Server = $PreferServer; IdentityType = 'Unresolved' }
}

# Call helper with resolved identity. Detect helper parameter names and adapt.
function Get-Members {
    param(
        [string]$ResolvedIdentity,
        [string]$Server,
        [switch]$IsDistinguishedName
    )

    $splat = @{
        GroupName = $ResolvedIdentity
        Fields    = $Fields
    }

    if ($Server) { $splat['Server'] = $Server }

    # Detect helper parameter names
    $helperParams = @()
    try {
        $helperCmd = Get-Command -Name Get-ActiveGroupMembers -CommandType Function -ErrorAction Stop
        $helperParams = $helperCmd.Parameters.Keys
    } catch {
        # If function not found, still attempt to call (the dot-sourced file may define a different shape)
    }

    # If identity looks like DN and helper accepts DistinguishedName or Identity, adapt
    if ($IsDistinguishedName -or ($ResolvedIdentity -match '^CN=.*DC=.*' -or $ResolvedIdentity -match '^OU=.*DC=.*')) {
        if ($helperParams -contains 'DistinguishedName') {
            $splat.Remove('GroupName') | Out-Null
            $splat['DistinguishedName'] = $ResolvedIdentity
        } elseif ($helperParams -contains 'Identity') {
            $splat.Remove('GroupName') | Out-Null
            $splat['Identity'] = $ResolvedIdentity
        }
    }

    # Forward IncludeDisabled/IncludeExpired if helper supports them
    if ($IncludeDisabled -and ($helperParams -contains 'IncludeDisabled')) { $splat['IncludeDisabled'] = $true }
    if ($IncludeExpired -and ($helperParams -contains 'IncludeExpired')) { $splat['IncludeExpired'] = $true }

    Write-DebugLine ("Calling Get-ActiveGroupMembers with: {0}" -f ($splat | Out-String))

    try {
        $members = & Get-ActiveGroupMembers @splat 2>&1
        return ,$members
    } catch {
        Write-Warning "Get-ActiveGroupMembers failed for '$ResolvedIdentity' (server: $Server): $($_.Exception.Message)"
        return @()
    }
}

# Compute preferred server values in a PS5.1-compatible way
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
    Write-Warning "One or both groups could not be conclusively resolved. The script will still attempt to call Get-ActiveGroupMembers with the best available values."
}

# Fetch members
$membersA = Get-Members -ResolvedIdentity $resolveA.Identity -Server $resolveA.Server -IsDistinguishedName:($resolveA.IdentityType -match 'DN|ResolvedDN')
$membersB = Get-Members -ResolvedIdentity $resolveB.Identity -Server $resolveB.Server -IsDistinguishedName:($resolveB.IdentityType -match 'DN|ResolvedDN')

# If both empty, exit with a helpful error
if (($membersA.Count -eq 0) -and ($membersB.Count -eq 0)) {
    Write-Error "No members returned for either group. Verify connectivity, credentials, and that Get-ActiveGroupMembers accepts server or identity formats used."
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