<#
.SYNOPSIS
    Export Active Directory group membership (optional) and Delinea zone/group membership to TSV files.

.DESCRIPTION
    Coordinates two phases:

      1) Active Directory phase (unless -SkipAD)
         - Finds groups matching -GroupPattern under -SearchDomain and -SearchBase
         - Expands membership recursively with cycle protection
         - Writes one TSV per group

      2) Delinea phase
         - Enumerates zones (optionally limited by -CdmRootZonePath)
         - Enumerates zone group profiles
         - Resolves backing Active Directory groups and expands their members on demand
         - Attempts to resolve per-zone Unix profile information for each user
         - Writes per-zone TSV outputs

    Caching can be enabled to reduce repeated Delinea lookups across runs.

.PARAMETER GroupPattern
    Wildcard pattern for group names (for example: "APP_*" ).

.PARAMETER SearchDomain
    Domain DNS name or domain controller used for the Active Directory search.

.PARAMETER SearchBase
    OU path under which to search for groups. Slash or backslash separated (for example: "Infrastructure/Groups").

.PARAMETER OutputDir
    Directory to write TSV files. Created if missing.

.PARAMETER CdmRootZonePath
    Optional Delinea zone path to limit processing (for example: "Global Zone/Engineering").

.PARAMETER SkipAD
    Skip the Active Directory export phase.

.PARAMETER Full
    Overwrite existing TSV outputs instead of skipping them.

.PARAMETER ProcessAllDelineaGroups
    Process all Delinea groups found, not just those whose associated AD group matches -GroupPattern.

.PARAMETER LoadCache
    Load a previously saved Delinea lookup cache.

.PARAMETER WriteCache
    Save the in-memory Delinea lookup cache at the end of processing.

.PARAMETER CachePath
    Optional CLIXML cache path. Defaults to "<OutputDir>\delinea-user-cache.clixml".

.EXAMPLE
    PS C:\> .\Export-ADAndDelinea.ps1 -GroupPattern "APP_*" -SearchDomain example.com -SearchBase "Infrastructure/Groups" -OutputDir .\exports

.EXAMPLE
    PS C:\> .\Export-ADAndDelinea.ps1 -GroupPattern "APP_*" -SearchDomain example.com -SearchBase "Groups" -OutputDir .\exports -CdmRootZonePath "Global Zone/Engineering" -LoadCache -WriteCache

.NOTES
    Requires:
      - ActiveDirectory module (RSAT: Active Directory tools)
      - Centrify.DirectControl.PowerShell (Delinea) for the Delinea phase
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$GroupPattern,

    [Parameter(Mandatory = $true)]
    [string]$SearchDomain,

    [Parameter(Mandatory = $true)]
    [string]$SearchBase,

    [Parameter(Mandatory = $true)]
    [string]$OutputDir,

    [string]$CdmRootZonePath,

    [switch]$SkipAD,
    [switch]$Full,
    [switch]$ProcessAllDelineaGroups,

    [switch]$LoadCache,
    [switch]$WriteCache,
    [string]$CachePath
)

############################################################
# Helpers
############################################################
function Convert-ToLdapSearchBase {
    param($SearchDomain, $OuPath)
    $dcParts = $SearchDomain.Split('.') | ForEach-Object { "DC=$_" }
    $dcDn = $dcParts -join ','
    $ouParts = $OuPath -split '[\\/]' | Where-Object { $_ }
    [array]::Reverse($ouParts)
    $ouDn = $ouParts | ForEach-Object { "OU=$_" }
    $ouDn = $ouDn -join ','
    if ($ouDn) { "$ouDn,$dcDn" } else { $dcDn }
}

function Get-DomainFromDN {
    param([string]$DN)
    if (-not $DN) { return $null }
    $dcs = [regex]::Matches($DN, 'DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value }
    if ($dcs.Count -gt 0) { return ($dcs -join '.') }
    return $null
}

function Get-ADFolderFromCanonical {
    param([string]$CanonicalName)
    if (-not $CanonicalName) { return "" }
    $parts = $CanonicalName -split '/'
    if ($parts.Count -le 1) { return $CanonicalName }
    ($parts[0..($parts.Count - 2)] -join '/')
}

function Sanitize-FileName {
    param([string]$Name)
    $invalid = [IO.Path]::GetInvalidFileNameChars()
    foreach ($c in $invalid) {
        $Name = $Name -replace [regex]::Escape($c), '_'
    }
    $Name
}

function Should-SkipFileVerbose {
    param(
        [string]$Path,
        [switch]$Full,
        [string]$Reason = "exists"
    )
    if ($Full) { return $false }
    if (-not (Test-Path $Path)) { return $false }
    $info = Get-Item $Path
    $age  = (Get-Date) - $info.LastWriteTime
    if ($age.TotalHours -gt 24) {
        Write-Warning "Skipping '$Path' (file >24h old; run with -Full to refresh)."
    } else {
        Write-Host "Skipping '$Path' ($Reason)." -ForegroundColor DarkGray
    }
    return $true
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

if (-not $CachePath) {
    $CachePath = Join-Path $OutputDir 'delinea-user-cache.clixml'
}

############################################################
# AD setup
############################################################
Import-Module ActiveDirectory

$ldapBase = Convert-ToLdapSearchBase $SearchDomain $SearchBase
$forest     = Get-ADForest
$domainList = $forest.Domains
$AdMembersByGroup = @{}

############################################################
# Cycle-safe AD group expansion
############################################################
function Get-AdGroupMembersRecursive {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.ActiveDirectory.Management.ADGroup]$GroupObj,
        [Parameter(Mandatory = $true)]
        [string]$PreferredServer,
        [Parameter(Mandatory = $true)]
        [string[]]$DomainList,
        [Parameter(Mandatory = $true)]
        [hashtable]$Visited
    )

    $results = @()

    $gKey = $GroupObj.DistinguishedName
    if ($Visited.ContainsKey($gKey)) {
        return @()
    }
    $Visited[$gKey] = $true

    $members = $null
    try {
        $members = Get-ADGroupMember -Server $PreferredServer -Identity $GroupObj -ErrorAction Stop
    } catch {
        foreach ($d in $DomainList) {
            try {
                $members = Get-ADGroupMember -Server $d -Identity $GroupObj -ErrorAction Stop
                if ($members) { break }
            } catch {}
        }
    }

    if (-not $members) { return @() }

    foreach ($m in $members) {
        if ($m.objectClass -eq 'user' -and $m.DistinguishedName) {
            $userDomain = Get-DomainFromDN $m.DistinguishedName
            if ($userDomain) {
                $u = Get-ADUser -Server $userDomain -Identity $m.DistinguishedName -Properties Enabled,UserPrincipalName,CanonicalName -ErrorAction SilentlyContinue
                if ($u -and $u.Enabled) {
                    $results += [pscustomobject]@{
                        SamAccountName    = $u.SamAccountName
                        UserPrincipalName = $u.UserPrincipalName
                        ADSFolder         = Get-ADFolderFromCanonical $u.CanonicalName
                    }
                } else {
                    $results += [pscustomobject]@{
                        SamAccountName    = $m.Name
                        UserPrincipalName = ""
                        ADSFolder         = "UNRESOLVED (user disabled or missing)"
                    }
                }
            } else {
                $results += [pscustomobject]@{
                    SamAccountName    = $m.Name
                    UserPrincipalName = ""
                    ADSFolder         = "UNRESOLVED (no DN domain)"
                }
            }
        }
        elseif ($m.objectClass -eq 'group') {
            $childDomain = $null
            if ($m.DistinguishedName) {
                $childDomain = Get-DomainFromDN $m.DistinguishedName
            }
            if (-not $childDomain) { $childDomain = $PreferredServer }
            $childGroup = Get-ADGroup -Server $childDomain -Identity $m.DistinguishedName -ErrorAction SilentlyContinue
            if ($childGroup) {
                $results += Get-AdGroupMembersRecursive -GroupObj $childGroup -PreferredServer $childDomain -DomainList $DomainList -Visited $Visited
            }
        }
        elseif ($m.objectClass -eq 'foreignSecurityPrincipal' -and $m.SID) {
            $resolved = $false
            foreach ($d in $DomainList) {
                $u = Get-ADUser -Server $d -Identity $m.SID -Properties Enabled,UserPrincipalName,CanonicalName -ErrorAction SilentlyContinue
                if ($u -and $u.Enabled) {
                    $results += [pscustomobject]@{
                        SamAccountName    = $u.SamAccountName
                        UserPrincipalName = $u.UserPrincipalName
                        ADSFolder         = Get-ADFolderFromCanonical $u.CanonicalName
                    }
                    $resolved = $true
                    break
                }
            }
            if (-not $resolved) {
                $results += [pscustomobject]@{
                    SamAccountName    = $m.Name
                    UserPrincipalName = ""
                    ADSFolder         = "UNRESOLVED-FSP"
                }
            }
        }
        else {
            $results += [pscustomobject]@{
                SamAccountName    = $m.Name
                UserPrincipalName = ""
                ADSFolder         = "NON-USER"
            }
        }
    }

    return $results
}

############################################################
# On-demand AD group fetch
############################################################
function Get-AdGroupMembersOnDemand {
    param(
        [string]$GroupName,
        [string]$SearchDomain,
        [string]$LdapBase,
        [string[]]$DomainList
    )

    if ($AdMembersByGroup.ContainsKey($GroupName)) {
        return $AdMembersByGroup[$GroupName]
    }

    $g = Get-ADGroup -Server $SearchDomain -SearchBase $LdapBase -SearchScope Subtree -Filter "name -eq '$GroupName'" -ErrorAction SilentlyContinue

    if (-not $g) {
        foreach ($dom in $DomainList) {
            $g = Get-ADGroup -Server $dom -Filter "name -eq '$GroupName'" -ErrorAction SilentlyContinue
            if ($g) { break }
        }
    }

    if (-not $g) {
        Write-Host "  (on-demand) AD group '$GroupName' not found in any domain." -ForegroundColor DarkGray
        $AdMembersByGroup[$GroupName] = @()
        return @()
    }

    $groupDomain = Get-DomainFromDN $g.DistinguishedName
    if (-not $groupDomain) { $groupDomain = $SearchDomain }

    $visited = @{}
    try {
        $members = Get-AdGroupMembersRecursive -GroupObj $g -PreferredServer $groupDomain -DomainList $DomainList -Visited $visited
    } catch {
        Write-Host "  (on-demand) AD group '$GroupName' was found but members could not be read." -ForegroundColor DarkYellow
        $AdMembersByGroup[$GroupName] = @()
        return @()
    }

    $members = $members | Sort-Object SamAccountName, UserPrincipalName, ADSFolder -Unique
    $AdMembersByGroup[$GroupName] = $members
    Write-Host "  (on-demand) pulled AD group '$GroupName' with $($members.Count) members from '$groupDomain'." -ForegroundColor DarkCyan
    return $members
}

############################################################
# AD phase
############################################################
if (-not $SkipAD) {
    Write-Host "=== AD phase starting ==="
    $adGroups = Get-ADGroup -Server $SearchDomain -SearchBase $ldapBase -SearchScope Subtree -Filter "name -like '$GroupPattern'" -ErrorAction SilentlyContinue
    if (-not $adGroups) {
        Write-Warning "No AD groups found for pattern '$GroupPattern' under $SearchBase."
    } else {
        Write-Host "Found $($adGroups.Count) AD groups matching '$GroupPattern'."
        foreach ($grp in $adGroups) {
            Write-Host "AD: processing group '$($grp.Name)'" -ForegroundColor Cyan
            $adFile = Join-Path $OutputDir ("ad-" + (Sanitize-FileName $grp.Name) + ".tsv")

            $members = Get-AdGroupMembersOnDemand -GroupName $grp.Name -SearchDomain $SearchDomain -LdapBase $ldapBase -DomainList $domainList

            if (Should-SkipFileVerbose -Path $adFile -Full:$Full -Reason "AD file already exists") {
                continue
            }

            if ($members.Count -gt 0) {
                $lines = @("SamAccountName`tUserPrincipalName`tActiveDirectoryDomainServicesFolder")
                $lines += $members | ForEach-Object {
                    "$($_.SamAccountName)`t$($_.UserPrincipalName)`t$($_.ADSFolder)"
                }
                $lines | Set-Content -Path $adFile -Encoding UTF8
                Write-Host "AD: wrote $adFile"
            } else {
                Write-Host "AD: group '$($grp.Name)' had no members." -ForegroundColor DarkYellow
            }
        }
    }
} else {
    Write-Host "=== AD phase skipped (-SkipAD) ==="
}

############################################################
# Delinea phase
############################################################
Write-Host "=== Delinea phase starting ==="

$DelineaAvailable  = $false
$AllZones          = @()
$ZoneByDn          = @{}
$DelineaUserCache  = @{}
$DelineaNotFound   = [pscustomobject]@{ NotFound = $true }

try {
    Import-Module Centrify.DirectControl.PowerShell -ErrorAction Stop
    $DelineaAvailable = $true
    Write-Host "Delinea module loaded." -ForegroundColor Green
} catch {
    Write-Warning "Delinea module not available; skipping Delinea phase."
}

if ($LoadCache -and (Test-Path $CachePath)) {
    try {
        $loaded = Import-Clixml -Path $CachePath
        if ($loaded -is [hashtable]) {
            $DelineaUserCache = $loaded
            Write-Host "Loaded Delinea cache from ${CachePath} (entries: $($DelineaUserCache.Count))"
        }
    } catch {
        Write-Warning "Could not load cache from ${CachePath}: $($_.Exception.Message)"
    }
}

function Get-CachedDelineaProfile {
    param(
        [string]$ZoneKey,
        [string]$UserKey
    )
    if (-not $ZoneKey -or -not $UserKey) { return $null }
    $fullKey = ($ZoneKey + "|" + $UserKey.ToLower())
    if ($script:DelineaUserCache.ContainsKey($fullKey)) {
        return $script:DelineaUserCache[$fullKey]
    }
    return $null
}

function Set-CachedDelineaProfile {
    param(
        [string]$ZoneKey,
        [string[]]$UserKeys,
        $Profile,
        $NotFoundSentinel
    )
    if (-not $ZoneKey) { return }
    foreach ($k in $UserKeys) {
        if (-not $k) { continue }
        $fullKey = ($ZoneKey + "|" + $k.ToLower())
        if ($Profile) {
            $script:DelineaUserCache[$fullKey] = $Profile
        } else {
            $script:DelineaUserCache[$fullKey] = $NotFoundSentinel
        }
    }
}

if ($DelineaAvailable) {

    $AllZones = Get-CdmZone -ErrorAction SilentlyContinue
    if (-not $AllZones) {
        Write-Warning "Get-CdmZone returned no zones; skipping Delinea."
        $DelineaAvailable = $false
    } else {
        foreach ($z in $AllZones) {
            if ($z.DistinguishedName) {
                $ZoneByDn[$z.DistinguishedName] = $z
            }
        }

        if ($CdmRootZonePath) {
            $parts = $CdmRootZonePath -split '[\\/]' | Where-Object { $_ }
            $first = $parts[0]
            $candidateRoots = $AllZones | Where-Object { $_.Name -eq $first }
            if ($candidateRoots.Count -gt 1) {
                $candidateRoots = $candidateRoots | Where-Object { $_.CanonicalName -like "*$first*" }
            }
            $currentCandidates = $candidateRoots

            for ($i = 1; $i -lt $parts.Count; $i++) {
                $p = $parts[$i]
                $next = @()
                foreach ($parentZone in $currentCandidates) {
                    $strict = $AllZones | Where-Object { $_.Name -eq $p -and $_.Parent -eq $parentZone.DistinguishedName }
                    if ($strict) {
                        $next += $strict
                    } else {
                        $loose = $AllZones | Where-Object { $_.Name -eq $p -and $_.CanonicalName -like "*$($parentZone.Name)*" }
                        if ($loose) { $next += $loose }
                    }
                }
                $currentCandidates = $next
                if (-not $currentCandidates -or $currentCandidates.Count -eq 0) { break }
            }

            if ($currentCandidates -and $currentCandidates.Count -gt 0) {
                $resolvedDns = $currentCandidates | ForEach-Object { $_.DistinguishedName }
                $AllZones = $AllZones | Where-Object {
                    $match = $false
                    foreach ($rdn in $resolvedDns) {
                        if ($_.DistinguishedName -eq $rdn -or ($_.Parent -and $_.Parent -like "*$rdn*")) {
                            $match = $true; break
                        }
                    }
                    $match
                }
                Write-Host "Delinea: limited to subtree '$CdmRootZonePath' ($($AllZones.Count) zone(s))." -ForegroundColor Green
            } else {
                $last = $parts[-1]
                $matched = $AllZones | Where-Object { $_.Name -eq $last }
                if ($matched) {
                    $AllZones = $matched
                    Write-Warning "Could not strictly resolve '$CdmRootZonePath'; limiting to zones named '$last' ($($AllZones.Count) zone(s))."
                } else {
                    Write-Warning "Could not resolve Delinea path '$CdmRootZonePath'; using all zones."
                }
            }
        } else {
            Write-Host "Delinea: will process $($AllZones.Count) zones."
        }
    }
}

function Get-ZonePath {
    param($Zone)
    if (-not $Zone) { return "UnknownZone" }
    if ($Zone.DistinguishedName -and $ZoneByDn.Count -gt 0) {
        $parts = @()
        $current = $Zone
        while ($current) {
            $parts += $current.Name
            if ($current.Parent -and $ZoneByDn.ContainsKey($current.Parent)) {
                $current = $ZoneByDn[$current.Parent]
            } else {
                $current = $null
            }
        }
        [array]::Reverse($parts)
        return ($parts -join "-")
    }
    return $Zone.Name
}

function Get-CdmUserProfileSafe {
    param($Zone, [string]$UserName)
    try {
        return Get-CdmUserProfile -Zone $Zone -User $UserName -ErrorAction Stop
    } catch { return $null }
}

function Get-CdmUserProfileCascade {
    param(
        $StartZone,
        [string]$UserName,
        [int]$MaxHops = 3
    )
    $current = $StartZone
    $hops = 0
    while ($current -and $hops -lt $MaxHops) {
        $prof = Get-CdmUserProfileSafe -Zone $current -UserName $UserName
        if ($prof) { return $prof }
        if ($current.Parent -and $ZoneByDn.ContainsKey($current.Parent)) {
            $current = $ZoneByDn[$current.Parent]
            $hops++
        } else {
            $current = $null
        }
    }
    return $null
}

if ($DelineaAvailable) {

    foreach ($zone in $AllZones) {

        Write-Host "Delinea: zone '$($zone.Name)'" -ForegroundColor Cyan

        $zonePath     = Get-ZonePath $zone
        $safeZonePath = Sanitize-FileName $zonePath

        # 1) write zone group list
        $zoneGroupFile = Join-Path $OutputDir ("delinea-" + $safeZonePath + "-groups.tsv")
        if (-not (Should-SkipFileVerbose -Path $zoneGroupFile -Full:$Full -Reason "zone group list exists")) {
            $zoneGroups = Get-CdmGroupProfile -Zone $zone -ErrorAction SilentlyContinue
            $lines = @("GroupName`tADGroupName`tZonePath`tUnixGid")
            if ($zoneGroups) {
                foreach ($gp in $zoneGroups) {
                    $lines += "$($gp.Name)`t$($gp.Group)`t$zonePath`t$($gp.Gid)"
                }
            }
            $lines | Set-Content -Path $zoneGroupFile -Encoding UTF8
            Write-Host "  wrote $zoneGroupFile"
        }

        # 2) per-group users
        $zoneGroups2 = Get-CdmGroupProfile -Zone $zone -ErrorAction SilentlyContinue
        if (-not $zoneGroups2) {
            Write-Host "  (no group profiles in this zone)" -ForegroundColor DarkGray
            continue
        }

        foreach ($gp in $zoneGroups2) {

            $adName = $null
            if ($gp.Group) {
                $adName = ($gp.Group -split '@')[0]
            } else {
                $adName = $gp.Name
            }
            if (-not $adName) { continue }

            if (-not $ProcessAllDelineaGroups) {
                if ($adName -notlike $GroupPattern) {
                    Write-Host "  skipping zone group '$($gp.Name)' (AD group '$adName' does not match '$GroupPattern')" -ForegroundColor DarkGray
                    continue
                }
            }

            $adMembers = @()
            if ($AdMembersByGroup.ContainsKey($adName)) {
                $adMembers = $AdMembersByGroup[$adName]
            } else {
                $adMembers = Get-AdGroupMembersOnDemand -GroupName $adName -SearchDomain $SearchDomain -LdapBase $ldapBase -DomainList $domainList
            }

            if (-not $adMembers -or $adMembers.Count -eq 0) {
                Write-Host "  skipping zone group '$($gp.Name)' (AD group '$adName' has no members)" -ForegroundColor DarkGray
                continue
            }

            $zoneGroupUsersFile = Join-Path $OutputDir ("delinea-" + $safeZonePath + "-" + (Sanitize-FileName $adName) + "-users.tsv")
            if (Should-SkipFileVerbose -Path $zoneGroupUsersFile -Full:$Full -Reason "zone+group users exists") {
                continue
            }

            $userLines = @("SamAccountName`tUserPrincipalName`tZonePath`tUnixLogin`tUnixUid`tPrimaryGroupId")

            $idx = 0
            $tot = $adMembers.Count
            foreach ($usr in $adMembers) {
                $idx++

                $unixLogin = "UID NOT FOUND"
                $unixUid   = "UID NOT FOUND"
                $primary   = ""

                $zoneKey = $zone.DistinguishedName
                if (-not $zoneKey) { $zoneKey = $zone.Name }

                $candidates = @()
                if ($usr.UserPrincipalName) { $candidates += $usr.UserPrincipalName }
                if ($usr.SamAccountName -and $zone.Domain) { $candidates += ("{0}@{1}" -f $usr.SamAccountName, $zone.Domain) }
                if ($usr.SamAccountName) { $candidates += $usr.SamAccountName }

                $prof = $null
                $cached = $false
                foreach ($cand in $candidates) {
                    $cachedVal = Get-CachedDelineaProfile -ZoneKey $zoneKey -UserKey $cand
                    if ($cachedVal) {
                        if ($cachedVal -is [pscustomobject] -and $cachedVal.PSObject.Properties.Name -contains 'NotFound') {
                            Write-Host "    [$idx/$tot] cache hit (NOT FOUND) for user '$($usr.SamAccountName)'" -ForegroundColor DarkGray
                            $cached = $true
                            $prof   = $null
                            break
                        } else {
                            Write-Host "    [$idx/$tot] cache hit for user '$($usr.SamAccountName)'" -ForegroundColor DarkGray
                            $cached = $true
                            $prof   = $cachedVal
                            break
                        }
                    }
                }

                if (-not $cached) {
                    Write-Host "    [$idx/$tot] resolving user '$($usr.SamAccountName)'" -ForegroundColor DarkGray

                    foreach ($cand in $candidates) {
                        if (-not $cand) { continue }
                        $prof = Get-CdmUserProfileCascade -StartZone $zone -UserName $cand -MaxHops 3
                        if ($prof) {
                            Set-CachedDelineaProfile -ZoneKey $zoneKey -UserKeys $candidates -Profile $prof -NotFoundSentinel $DelineaNotFound
                            $unixLogin = $prof.Name
                            $unixUid   = $prof.Uid
                            $primary   = $prof.PrimaryGroupId
                            break
                        }
                    }

                    if (-not $prof) {
                        Set-CachedDelineaProfile -ZoneKey $zoneKey -UserKeys $candidates -Profile $null -NotFoundSentinel $DelineaNotFound
                    }
                } else {
                    if ($prof) {
                        $unixLogin = $prof.Name
                        $unixUid   = $prof.Uid
                        $primary   = $prof.PrimaryGroupId
                    }
                }

                $userLines += "$($usr.SamAccountName)`t$($usr.UserPrincipalName)`t$zonePath`t$unixLogin`t$unixUid`t$primary"
            }

            $userLines | Set-Content -Path $zoneGroupUsersFile -Encoding UTF8
            Write-Host "  wrote $zoneGroupUsersFile"

            if ($WriteCache) {
                try {
                    $DelineaUserCache | Export-Clixml -Path $CachePath
                } catch {
                    Write-Warning "Could not write cache to ${CachePath}: $($_.Exception.Message)"
                }
            }

            Write-Host "Delinea cache size: $($DelineaUserCache.Count)" -ForegroundColor DarkGray
        }
    }
}

Write-Host "Done."