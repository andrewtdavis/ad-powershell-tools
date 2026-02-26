<#
.SYNOPSIS
  Compare members of two AD groups across domains with automatic domain inference.

.DESCRIPTION
  Dot-sources Get-ActiveGroupMembers.ps1 (assumes it lives in the same folder).
  Attempts to infer domain/server for each group; supports -DomainA/-DomainB or -Domain (single).
  Avoids interactive prompts from the helper by resolving identities before calling it.

.PARAMETER GroupA
  First group (positional). Can be: samAccountName, "DOMAIN\Group", distinguishedName, GUID, or UPN.

.PARAMETER GroupB
  Second group (positional).

.PARAMETER DomainA
  Optional domain/DC to use for GroupA (e.g. dc1.corp.example.com or corp.example.com).

.PARAMETER DomainB
  Optional domain/DC to use for GroupB.

.PARAMETER Domain
  Optional single domain to use for both groups.

.PARAMETER UseGlobalCatalog
  Switch: try a Global Catalog (3268) lookup as a last-resort.

.PARAMETER AutoResolve
  Switch (default: $true): try to resolve groups before calling helper. Set to $false to pass args verbatim.

.PARAMETER KeyField
  Field to use for member matching (default: SamAccountName).

.PARAMETER Fields
  Fields to show/export (default SamAccountName,Name,Email).

.PARAMETER CsvOut
  Path prefix for CSV export.

.EXAMPLE
  .\Compare-ActiveGroupMembers.ps1 CoreHPC_base CoreHPC_Tier1 -Domain sde.net.ucsf.edu

.EXAMPLE (explicit per-domain)
  .\Compare-ActiveGroupMembers.ps1 CoreHPC_base CoreHPC_Tier1 -DomainA corpA -DomainB corpB

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$GroupA,

    [Parameter(Mandatory=$true, Position=1)]
    [string]$GroupB,

    [string]$DomainA,
    [string]$DomainB,
    [Alias('domain')]
    [string]$Domain,

    [switch]$UseGlobalCatalog,

    [switch]$AutoResolve = $true,

    [string]$KeyField = 'SamAccountName',
    [string[]]$Fields = @('SamAccountName','Name','Email'),

    [Parameter(Mandatory=$false)]
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

function Write-DebugLine { param($s) if ($PSBoundParameters.ContainsKey('Verbose')) { Write-Verbose $s } }

# Try to resolve a group to an identity and a server to query.
function Resolve-Group {
    param(
        [string]$GroupInput,
        [string]$PreferServer   # domain or server to try first (optional)
    )

    # Return object: @{ Identity = <what we'll pass to helper>; Server = <server to pass or $null>; IdentityType = 'DN'|'SAM'|'UPN'|'GUID'|'Raw' }
    # If AutoResolve - we attempt to confirm the object exists (using Get-ADGroup) and return definitive info.
    # Accept inputs that already look like DN or domain\sam or GUID or UPN.

    # Quick pattern checks
    if ($GroupInput -match '^CN=.*DC=.*' -or $GroupInput -match '^OU=.*DC=.*') {
        return @{ Identity = $GroupInput; Server = $null; IdentityType = 'DN' }
    }
    if ($GroupInput -match '^[^\\]+\\.+') {
        # domain\group form (or NETBIOS\group)
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
        # UPN-like
        return @{ Identity = $GroupInput; Server = $null; IdentityType = 'UPN' }
    }

    # If AutoResolve is off, pass the raw string; allow Domain preference
    if (-not $AutoResolve) {
        $server = $PreferServer
        return @{ Identity = $GroupInput; Server = $server; IdentityType = 'Raw' }
    }

    # Try local lookup (no -Server)
    try {
        Write-DebugLine "Attempting Get-ADGroup -Identity '$GroupInput' (no server)..."
        $g = Get-ADGroup -Identity $GroupInput -ErrorAction Stop
        # If found, return identity as distinguishedName and server null (we can query DC in that domain if needed)
        return @{ Identity = $g.DistinguishedName; Server = $g.DNSHostName; IdentityType = 'ResolvedDN' }
    } catch {
        # not found locally
        Write-DebugLine "Local lookup failed for '$GroupInput': $($_.Exception.Message)"
    }

    # If a prefer server / domain was given, try it
    if ($PreferServer) {
        try {
            Write-DebugLine "Attempting Get-ADGroup -Identity '$GroupInput' -Server '$PreferServer'..."
            $g2 = Get-ADGroup -Identity $GroupInput -Server $PreferServer -ErrorAction Stop
            return @{ Identity = $g2.DistinguishedName; Server = $PreferServer; IdentityType = 'ResolvedDN' }
        } catch {
            Write-DebugLine "Lookup at server '$PreferServer' failed: $($_.Exception.Message)"
        }
    }

    # If DomainA/DomainB/Domain parameters not provided, but UseGlobalCatalog requested, try GC
    if ($UseGlobalCatalog) {
        # Try GC by using :3268 on a GC host - letting AD choose by passing domain service name with :3268
        # If user passed simple domain (like example.com) try that; otherwise attempt to use default forest name with :3268
        $gcTry = $null
        if ($Domain) { $gcTry = "$Domain:3268" } elseif ($PreferServer) { $gcTry = "$PreferServer:3268" } else { $gcTry = (Get-ADDomainController -Filter {IsGlobalCatalog -eq $true} -ErrorAction SilentlyContinue | Select-Object -First 1).HostName + ":3268" }
        if ($gcTry) {
            try {
                Write-DebugLine "Attempting GC lookup - Server '$gcTry'..."
                $g3 = Get-ADGroup -Identity $GroupInput -Server $gcTry -ErrorAction Stop
                return @{ Identity = $g3.DistinguishedName; Server = $gcTry; IdentityType = 'ResolvedDN' }
            } catch {
                Write-DebugLine "GC lookup failed: $($_.Exception.Message)"
            }
        }
    }

    # Last attempts: try constructing a DC from Domain strings if they look like domains
    $candidates = @()
    if ($PreferServer) { $candidates += $PreferServer }
    if ($Domain) { $candidates += $Domain }
    if ($Domain -and ($Domain -notlike '*.*')) {
        # maybe NETBIOS; can't do much
    } else {
        # build a DC host candidate
        foreach ($d in $candidates | Where-Object { $_ }) {
            $tryHost = $d
            try {
                Write-DebugLine "Attempting Get-ADGroup -Identity '$GroupInput' -Server '$tryHost'..."
                $g4 = Get-ADGroup -Identity $GroupInput -Server $tryHost -ErrorAction Stop
                return @{ Identity = $g4.DistinguishedName; Server = $tryHost; IdentityType = 'ResolvedDN' }
            } catch {
                Write-DebugLine "Candidate server lookup failed: $($_.Exception.Message)"
            }
        }
    }

    # If nothing worked, return raw with prefer server (so helper can try its own resolution)
    return @{ Identity = $GroupInput; Server = $PreferServer; IdentityType = 'Unresolved' }
}

# Helper that calls Get-ActiveGroupMembers with appropriate splatting
function Get-Members {
    param(
        [string]$ResolvedIdentity,
        [string]$Server,
        [switch]$IsDistinguishedName
    )

    $splat = @{
        # default parameter name assumed: GroupName
        GroupName = $ResolvedIdentity
        Fields    = $Fields
    }

    # If helper supports -Server, include it; otherwise it will be ignored within helper if not recognized
    if ($Server) { $splat['Server'] = $Server }

    # If the resolved identity looks like a DN and helper expects DistinguishedName param, adapt here:
    # We'll attempt to detect if helper accepts -DistinguishedName by checking the function metadata
    $helperParams = (Get-Command -Name Get-ActiveGroupMembers -CommandType Function).Parameters.Keys
    if ($IsDistinguishedName -or ($ResolvedIdentity -match '^CN=.*DC=.*' -or $ResolvedIdentity -match '^OU=.*DC=.*')) {
        if ($helperParams -contains 'DistinguishedName') {
            $splat.Remove('GroupName') | Out-Null
            $splat['DistinguishedName'] = $ResolvedIdentity
        } elseif ($helperParams -contains 'Identity') {
            $splat.Remove('GroupName') | Out-Null
            $splat['Identity'] = $ResolvedIdentity
        } else {
            # leave as GroupName (many helpers accept DN in Identity param)
        }
    }

    # Add switches if helper supports them (IncludeDisabled etc.) - echoing original script capability
    if ($PSBoundParameters.ContainsKey('IncludeDisabled') -and $PSBoundParameters['IncludeDisabled']) {
        if ($helperParams -contains 'IncludeDisabled') { $splat['IncludeDisabled'] = $true }
    }
    if ($PSBoundParameters.ContainsKey('IncludeExpired') -and $PSBoundParameters['IncludeExpired']) {
        if ($helperParams -contains 'IncludeExpired') { $splat['IncludeExpired'] = $true }
    }

    Write-DebugLine "Calling Get-ActiveGroupMembers with: $($splat | Out-String)"
    try {
        $members = & Get-ActiveGroupMembers @splat 2>&1
        # if helper wrote errors or prompts, detect and abort
        if ($members -is [System.Management.Automation.ErrorRecord]) {
            throw $members
        }
        return ,$members
    } catch {
        Write-Warning "Get-ActiveGroupMembers failed for '$ResolvedIdentity' (server: $Server): $($_.Exception.Message)"
        return @()
    }
}

# Resolve both groups
$resolveA = Resolve-Group -GroupInput $GroupA -PreferServer ($DomainA ? $DomainA : $Domain)
$resolveB = Resolve-Group -GroupInput $GroupB -PreferServer ($DomainB ? $DomainB : $Domain)

Write-Host "Resolved GroupA: Identity = $($resolveA.Identity) Server = $($resolveA.Server) Type = $($resolveA.IdentityType)"
Write-Host "Resolved GroupB: Identity = $($resolveB.Identity) Server = $($resolveB.Server) Type = $($resolveB.IdentityType)"

# If unresolved and AutoResolve was on, warn user
if ($AutoResolve -and ($resolveA.IdentityType -eq 'Unresolved' -or $resolveB.IdentityType -eq 'Unresolved')) {
    Write-Warning "One or both groups couldn't be conclusively resolved. The script will still attempt to call Get-ActiveGroupMembers with the raw values; if your helper prompts for GroupName interactively that means it needs a different param form (use DistinguishedName, domain\\GroupName, or -Server)."
}

# Get member lists
$membersA = Get-Members -ResolvedIdentity $resolveA.Identity -Server $resolveA.Server -IsDistinguishedName:($resolveA.IdentityType -match 'DN|ResolvedDN')
$membersB = Get-Members -ResolvedIdentity $resolveB.Identity -Server $resolveB.Server -IsDistinguishedName:($resolveB.IdentityType -match 'DN|ResolvedDN')

# If helper returned nothing and AutoResolve was true but initial attempt was raw, offer a helpful hint and exit non-zero
if (($membersA.Count -eq 0) -and ($membersB.Count -eq 0)) {
    Write-Error "No members returned for either group. Check credentials, connectivity, and that Get-ActiveGroupMembers accepts -Server or the identity formats provided."
    exit 3
}

# Normalize KeyField and produce diffs (same approach as earlier)
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
    $keyn = if ($k) { $k.ToUpper() } else { [Guid]::NewGuid().ToString() } # avoid collisions on null
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

# Output results
Write-Host "--------------------------------------------------"
Write-Host "Members in '$GroupA' (resolved: $($resolveA.Identity)) but NOT in '$GroupB' (resolved: $($resolveB.Identity)): ($($inA_NotInB.Count))"
if ($inA_NotInB.Count -gt 0) { $inA_NotInB | Select-Object -Property $Fields | Format-Table -AutoSize } else { Write-Host "  <none>" }

Write-Host ""
Write-Host "Members in '$GroupB' (resolved: $($resolveB.Identity)) but NOT in '$GroupA' (resolved: $($resolveA.Identity)): ($($inB_NotInA.Count))"
if ($inB_NotInA.Count -gt 0) { $inB_NotInA | Select-Object -Property $Fields | Format-Table -AutoSize } else { Write-Host "  <none>" }
Write-Host "--------------------------------------------------"

# Optional CSV export
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