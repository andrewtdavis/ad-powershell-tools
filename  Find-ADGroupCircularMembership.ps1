 <#
.SYNOPSIS
  Find circular (cyclic) nested group membership starting from a given group.

.DESCRIPTION
  Starting from a specified group (Name/sAMAccountName/DN) in a specific domain,
  enumerates nested group-to-group membership edges and detects circular paths
  such as:
     GroupA -> GroupB -> GroupC -> GroupA

  Cross-domain nested groups are resolved by discovering the group’s domain
  from its DN and selecting an appropriate DC/GC in that domain.

  Notes:
    - Only group-to-group nesting is considered (users/computers are ignored).
    - This script explores the membership graph reachable from the start group.
    - Cycles are de-duplicated by a normalized key.

.PARAMETER Group
  Group identity: DistinguishedName (DN), sAMAccountName, or Name.

.PARAMETER Domain
  Domain FQDN (or a DC hostname) where the initial group lookup should occur
  when -Group is not a DN.

.PARAMETER MaxDepth
  Maximum nesting depth to explore (default: 25).

.PARAMETER IncludeDistributionGroups
  Include distribution groups (GroupCategory=Distribution). By default, only
  security groups are traversed.

.PARAMETER OutTsv
  Optional path to write results as TSV.

.PARAMETER PassThru
  Output objects to the pipeline as well as writing a summary.

.EXAMPLE
  .\Find-ADGroupCircularMembership.ps1 -Group "Finance-Admins" -Domain "example.com"

.EXAMPLE
  .\Find-ADGroupCircularMembership.ps1 -Group "CN=Finance-Admins,OU=Groups,DC=example,DC=com" -Domain example.com -OutTsv .\cycles.tsv

.EXAMPLE
  .\Find-ADGroupCircularMembership.ps1 -Group "Finance-Admins" -Domain "child.example.com" -MaxDepth 50 -PassThru
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$Group,

  [Parameter(Mandatory=$true)]
  [string]$Domain,

  [Parameter(Mandatory=$false)]
  [ValidateRange(1,500)]
  [int]$MaxDepth = 25,

  [Parameter(Mandatory=$false)]
  [switch]$IncludeDistributionGroups,

  [Parameter(Mandatory=$false)]
  [string]$OutTsv,

  [Parameter(Mandatory=$false)]
  [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-ADModule {
  if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "ActiveDirectory module not found. Install RSAT AD PowerShell or run on a domain-joined host with RSAT."
  }
  Import-Module ActiveDirectory -ErrorAction Stop
}

function Escape-LdapFilterValue {
  param([Parameter(Mandatory=$true)][string]$Value)
  # RFC 4515 escaping
  $Value = $Value -replace '\\', '\5c'
  $Value = $Value -replace '\*', '\2a'
  $Value = $Value -replace '\(', '\28'
  $Value = $Value -replace '\)', '\29'
  $Value = $Value -replace "`0", '\00'
  return $Value
}

function Get-DomainFromDN {
  param([Parameter(Mandatory=$true)][string]$DistinguishedName)
  # Extract DC= parts -> fqdn
  $dcs = @()
  foreach ($part in ($DistinguishedName -split ',')) {
    $p = $part.Trim()
    if ($p -match '^(?i)DC=(.+)$') { $dcs += $Matches[1] }
  }
  if (-not $dcs.Count) { return $null }
  return ($dcs -join '.').ToLowerInvariant()
}

function Get-ForestDomainMap {
  param([Parameter(Mandatory=$false)][string]$Server)

  $forest = if ($Server) { Get-ADForest -Server $Server } else { Get-ADForest }
  $map = @{}  # domain fqdn (lower) -> preferred DC hostname
  foreach ($d in $forest.Domains) {
    try {
      $dc = Get-ADDomainController -Discover -DomainName $d -Service "PrimaryDC"
      $map[$d.ToLowerInvariant()] = $dc.HostName
    } catch {
      # Fallback to any DC
      $dc = Get-ADDomainController -Discover -DomainName $d
      $map[$d.ToLowerInvariant()] = $dc.HostName
    }
  }

  $gcs = @()
  try {
    if ($forest.GlobalCatalogs) { $gcs = @($forest.GlobalCatalogs) }
  } catch {}

  if (-not $gcs.Count) {
    # Try discovering a GC from the root domain
    try {
      $root = $forest.RootDomain
      $gc = Get-ADDomainController -Discover -DomainName $root -Service GlobalCatalog
      $gcs = @($gc.HostName)
    } catch {}
  }

  return [pscustomobject]@{
    Forest = $forest
    DomainMap = $map
    GlobalCatalogs = $gcs
  }
}

function Get-ServerForDomain {
  param(
    [Parameter(Mandatory=$true)][string]$DomainName,
    [Parameter(Mandatory=$true)][hashtable]$DomainMap
  )

  $k = $DomainName.ToLowerInvariant()
  if ($DomainMap.ContainsKey($k) -and $DomainMap[$k]) { return $DomainMap[$k] }

  # Last-ditch: try discovery
  $dc = Get-ADDomainController -Discover -DomainName $DomainName
  return $dc.HostName
}

function Resolve-Group {
  param(
    [Parameter(Mandatory=$true)][string]$GroupId,
    [Parameter(Mandatory=$true)][string]$DefaultDomain,
    [Parameter(Mandatory=$true)][hashtable]$DomainMap
  )

  # If DN: domain is derived from DN
  if ($GroupId -match '(?i)\bDC=') {
    $dom = Get-DomainFromDN -DistinguishedName $GroupId
    if (-not $dom) { throw "Could not derive domain from DN: $GroupId" }
    $srv = Get-ServerForDomain -DomainName $dom -DomainMap $DomainMap
    return Get-ADGroup -Identity $GroupId -Server $srv -Properties DistinguishedName,SamAccountName,Name,GroupCategory,GroupScope,ObjectGUID
  }

  # Otherwise: look in DefaultDomain
  $srv = Get-ServerForDomain -DomainName $DefaultDomain -DomainMap $DomainMap

  # Try identity direct
  $g = Get-ADGroup -Identity $GroupId -Server $srv -ErrorAction SilentlyContinue -Properties DistinguishedName,SamAccountName,Name,GroupCategory,GroupScope,ObjectGUID
  if ($g) { return $g }

  # Try search by samAccountName or Name
  $safe = $GroupId.Replace("'", "''")
  $g = Get-ADGroup -Server $srv -Filter "SamAccountName -eq '$safe' -or Name -eq '$safe'" -ErrorAction SilentlyContinue -Properties DistinguishedName,SamAccountName,Name,GroupCategory,GroupScope,ObjectGUID | Select-Object -First 1
  if ($g) { return $g }

  throw "Unable to resolve group '$GroupId' in domain '$DefaultDomain' (server $srv)."
}

function Get-DomainControllersForDomain {
  param(
    [Parameter(Mandatory=$true)][string]$DomainName
  )

  # Prefer writable DCs; keep it simple and retry across several.
  try {
    $dcs = Get-ADDomainController -Filter * -Server $DomainName -ErrorAction Stop |
      Where-Object { $_.HostName } |
      Select-Object -ExpandProperty HostName
    if ($dcs) { return @($dcs | Sort-Object -Unique) }
  } catch {}

  # Last ditch discovery
  try {
    $dc = Get-ADDomainController -Discover -DomainName $DomainName -ErrorAction Stop
    if ($dc -and $dc.HostName) { return @($dc.HostName) }
  } catch {}

  return @()
}

function Get-DirectMemberDNsViaLdap {
  param(
    [Parameter(Mandatory=$true)][string]$GroupDN,
    [Parameter(Mandatory=$true)][string]$DomainName,
    [Parameter(Mandatory=$true)][string]$ServerHost
  )

  # Read group's "member" attribute; support ranged retrieval for big groups.
  $baseDn = ($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','

  $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$ServerHost/$baseDn")
  $ds = New-Object System.DirectoryServices.DirectorySearcher($root)

  $escapedDn = Escape-LdapFilterValue -Value $GroupDN
  $ds.Filter = "(&(objectClass=group)(distinguishedName=$escapedDn))"
  $ds.PageSize = 1000
  $ds.SearchScope = "Subtree"

  $members = New-Object 'System.Collections.Generic.List[string]'

  # First try plain "member"; if server returns partials, we range it.
  $ds.PropertiesToLoad.Clear()
  $null = $ds.PropertiesToLoad.Add("member")

  $res = $ds.FindOne()
  if (-not $res) { return @() }

  if ($res.Properties["member"] -and $res.Properties["member"].Count -gt 0) {
    foreach ($m in $res.Properties["member"]) { $members.Add([string]$m) }
    return @($members)
  }

  # Ranged retrieval
  $start = 0
  $step = 1500

  while ($true) {
    $rangeAttr = "member;range=$start-$($start + $step - 1)"

    $ds.PropertiesToLoad.Clear()
    $null = $ds.PropertiesToLoad.Add($rangeAttr)

    $r = $ds.FindOne()
    if (-not $r) { break }

    $propName = $null
    foreach ($k in $r.Properties.PropertyNames) {
      if ($k -like "member;range=*") { $propName = $k; break }
    }
    if (-not $propName) { break }

    foreach ($m in $r.Properties[$propName]) { $members.Add([string]$m) }

    if ($propName -match ';range=\d+-\*$') {
      break
    }

    $start += $step
  }

  return @($members)
}
function Get-DomainControllersForDomain {
  param(
    [Parameter(Mandatory=$true)][string]$DomainName
  )

  # Prefer writable DCs; keep it simple and retry across several.
  try {
    $dcs = Get-ADDomainController -Filter * -Server $DomainName -ErrorAction Stop |
      Where-Object { $_.HostName } |
      Select-Object -ExpandProperty HostName
    if ($dcs) { return @($dcs | Sort-Object -Unique) }
  } catch {}

  # Last ditch discovery
  try {
    $dc = Get-ADDomainController -Discover -DomainName $DomainName -ErrorAction Stop
    if ($dc -and $dc.HostName) { return @($dc.HostName) }
  } catch {}

  return @()
}

function Get-DirectMemberDNsViaLdap {
  param(
    [Parameter(Mandatory=$true)][string]$GroupDN,
    [Parameter(Mandatory=$true)][string]$DomainName,
    [Parameter(Mandatory=$true)][string]$ServerHost
  )

  # Read group's "member" attribute; support ranged retrieval for big groups.
  $baseDn = ($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','

  $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$ServerHost/$baseDn")
  $ds = New-Object System.DirectoryServices.DirectorySearcher($root)

  $escapedDn = Escape-LdapFilterValue -Value $GroupDN
  $ds.Filter = "(&(objectClass=group)(distinguishedName=$escapedDn))"
  $ds.PageSize = 1000
  $ds.SearchScope = "Subtree"

  $members = New-Object 'System.Collections.Generic.List[string]'

  # First try plain "member"; if server returns partials, we range it.
  $ds.PropertiesToLoad.Clear()
  $null = $ds.PropertiesToLoad.Add("member")

  $res = $ds.FindOne()
  if (-not $res) { return @() }

  if ($res.Properties["member"] -and $res.Properties["member"].Count -gt 0) {
    foreach ($m in $res.Properties["member"]) { $members.Add([string]$m) }
    return @($members)
  }

  # Ranged retrieval
  $start = 0
  $step = 1500

  while ($true) {
    $rangeAttr = "member;range=$start-$($start + $step - 1)"

    $ds.PropertiesToLoad.Clear()
    $null = $ds.PropertiesToLoad.Add($rangeAttr)

    $r = $ds.FindOne()
    if (-not $r) { break }

    $propName = $null
    foreach ($k in $r.Properties.PropertyNames) {
      if ($k -like "member;range=*") { $propName = $k; break }
    }
    if (-not $propName) { break }

    foreach ($m in $r.Properties[$propName]) { $members.Add([string]$m) }

    if ($propName -match ';range=\d+-\*$') {
      break
    }

    $start += $step
  }

  return @($members)
}

function Get-NestedGroupMembers {
  param(
    [Parameter(Mandatory=$true)][object]$GroupObj,
    [Parameter(Mandatory=$true)][hashtable]$DomainMap,
    [Parameter(Mandatory=$true)][bool]$AllowDistribution
  )

  $dn = $GroupObj.DistinguishedName
  $dom = Get-DomainFromDN -DistinguishedName $dn
  if (-not $dom) { return @() }

  $dcCandidates = @()

  # Prefer the mapped DC first if we have one, then the rest of the domain DCs.
  try {
    $preferred = Get-ServerForDomain -DomainName $dom -DomainMap $DomainMap
    if ($preferred) { $dcCandidates += $preferred }
  } catch {}

  $dcCandidates += (Get-DomainControllersForDomain -DomainName $dom)
  $dcCandidates = @($dcCandidates | Where-Object { $_ } | Sort-Object -Unique)

  if (-not $dcCandidates.Count) { return @() }

  # 1) Try ADWS path via Get-ADGroupMember across DC candidates
  foreach ($srv in $dcCandidates) {
    try {
      $members = Get-ADGroupMember -Identity $dn -Server $srv -ErrorAction Stop
      if (-not $members) { return @() }

      $groups = @()
      foreach ($m in $members) {
        if ($m.objectClass -ne "group") { continue }

        try {
          $mdn = $m.DistinguishedName
          $mdom = Get-DomainFromDN -DistinguishedName $mdn
          if (-not $mdom) { continue }

          # Resolve nested group in its own domain (may differ)
          $nestedSrv = Get-ServerForDomain -DomainName $mdom -DomainMap $DomainMap
          $mg = Get-ADGroup -Identity $mdn -Server $nestedSrv -Properties DistinguishedName,SamAccountName,Name,GroupCategory,GroupScope,ObjectGUID -ErrorAction Stop

          if (-not $AllowDistribution -and $mg.GroupCategory -ne "Security") { continue }
          $groups += $mg
        } catch {
          continue
        }
      }

      return $groups
    } catch {
      # Try next DC
      continue
    }
  }

  # 2) Fallback: pure LDAP read of "member" (direct members only), then resolve groups
  foreach ($srv in $dcCandidates) {
    try {
      $memberDns = Get-DirectMemberDNsViaLdap -GroupDN $dn -DomainName $dom -ServerHost $srv
      if (-not $memberDns) { return @() }

      $out = @()
      foreach ($mdn in $memberDns) {
        $mdom = Get-DomainFromDN -DistinguishedName $mdn
        if (-not $mdom) { continue }

        try {
          $nestedSrv = Get-ServerForDomain -DomainName $mdom -DomainMap $DomainMap
          $mg = Get-ADGroup -Identity $mdn -Server $nestedSrv -Properties DistinguishedName,SamAccountName,Name,GroupCategory,GroupScope,ObjectGUID -ErrorAction Stop

          if (-not $AllowDistribution -and $mg.GroupCategory -ne "Security") { continue }
          $out += $mg
        } catch {
          continue
        }
      }

      return $out
    } catch {
      continue
    }
  }

  return @()
}

function Format-GroupLabel {
  param([Parameter(Mandatory=$true)][object]$GroupObj)
  $dom = Get-DomainFromDN -DistinguishedName $GroupObj.DistinguishedName
  $sam = $GroupObj.SamAccountName
  if (-not $sam) { $sam = $GroupObj.Name }
  if (-not $dom) { return $sam }
  return "$sam@$dom"
}

function Export-Tsv {
  param(
    [Parameter(Mandatory=$true)][object[]]$Rows,
    [Parameter(Mandatory=$true)][string]$Path
  )
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

  $Rows |
    ConvertTo-Csv -NoTypeInformation -Delimiter "`t" |
    ForEach-Object { $_ -replace '"', '' } |
    Set-Content -Path $Path -Encoding UTF8
}

# ---------------- main ----------------
Ensure-ADModule

$forestInfo = Get-ForestDomainMap -Server $Domain
$domainMap = $forestInfo.DomainMap

$start = Resolve-Group -GroupId $Group -DefaultDomain $Domain -DomainMap $domainMap
$allowDist = [bool]$IncludeDistributionGroups

if (-not $allowDist -and $start.GroupCategory -ne "Security") {
  throw "Start group '$($start.Name)' is not a Security group. Use -IncludeDistributionGroups if you want to traverse distribution groups."
}

# Caches
$groupByDn = @{}     # dn -> group object
$childrenByDn = @{}  # dn -> child dn array

function Get-ChildrenDnsCached {
  param([Parameter(Mandatory=$true)][object]$GroupObj)

  $dn = $GroupObj.DistinguishedName
  if ($childrenByDn.ContainsKey($dn)) { return $childrenByDn[$dn] }

  $kids = Get-NestedGroupMembers -GroupObj $GroupObj -DomainMap $domainMap -AllowDistribution $allowDist
  foreach ($k in $kids) { $groupByDn[$k.DistinguishedName] = $k }
  $childrenByDn[$dn] = @($kids | ForEach-Object { $_.DistinguishedName })
  return $childrenByDn[$dn]
}

# Cycle detection
$visited = New-Object 'System.Collections.Generic.HashSet[string]'
$inStack = New-Object 'System.Collections.Generic.HashSet[string]'
$path = New-Object 'System.Collections.Generic.List[string]'

$cycleKeys = New-Object 'System.Collections.Generic.HashSet[string]'
$cycles = New-Object 'System.Collections.Generic.List[object]'

function Normalize-CycleKey {
  param([Parameter(Mandatory=$true)][string[]]$CycleDns)
  # Create a stable key independent of rotation:
  # find lexicographically smallest DN and rotate cycle to start there.
  # CycleDns is expected to end with the repeated start DN.
  $core = $CycleDns[0..($CycleDns.Count-2)]
  $min = $core | Sort-Object | Select-Object -First 1
  $idx = [Array]::IndexOf($core, $min)
  if ($idx -lt 0) { $idx = 0 }

  $rot = @()
  for ($i=0; $i -lt $core.Count; $i++) {
    $rot += $core[($idx + $i) % $core.Count]
  }
  # close it
  $rot += $rot[0]
  return ($rot -join " -> ")
}

function DFS {
  param(
    [Parameter(Mandatory=$true)][string]$CurrentDn,
    [Parameter(Mandatory=$true)][int]$Depth
  )

  if ($Depth -gt $MaxDepth) { return }

  $null = $visited.Add($CurrentDn)
  $null = $inStack.Add($CurrentDn)
  $path.Add($CurrentDn) | Out-Null

  if (-not $groupByDn.ContainsKey($CurrentDn)) {
    # Resolve minimal info if not cached
    $dom = Get-DomainFromDN -DistinguishedName $CurrentDn
    if ($dom) {
      try {
        $srv = Get-ServerForDomain -DomainName $dom -DomainMap $domainMap
        $g = Get-ADGroup -Identity $CurrentDn -Server $srv -Properties DistinguishedName,SamAccountName,Name,GroupCategory,GroupScope,ObjectGUID
        $groupByDn[$CurrentDn] = $g
      } catch {}
    }
  }

  $curObj = $groupByDn[$CurrentDn]
  $childDns = @()
  if ($curObj) {
    $childDns = Get-ChildrenDnsCached -GroupObj $curObj
  }

  foreach ($childDn in $childDns) {
    if ($inStack.Contains($childDn)) {
      # Found a back-edge => cycle. Extract from first occurrence of childDn in current path.
      $startIdx = $path.IndexOf($childDn)
      if ($startIdx -ge 0) {
        $cycleDns = @()
        for ($i=$startIdx; $i -lt $path.Count; $i++) { $cycleDns += $path[$i] }
        $cycleDns += $childDn

        $key = Normalize-CycleKey -CycleDns $cycleDns
        if ($cycleKeys.Add($key)) {
          # Materialize labels
          $labels = @()
          foreach ($dn in $cycleDns) {
            if (-not $groupByDn.ContainsKey($dn)) {
              $dom = Get-DomainFromDN -DistinguishedName $dn
              if ($dom) {
                try {
                  $srv = Get-ServerForDomain -DomainName $dom -DomainMap $domainMap
                  $groupByDn[$dn] = Get-ADGroup -Identity $dn -Server $srv -Properties DistinguishedName,SamAccountName,Name,GroupCategory,GroupScope,ObjectGUID
                } catch {}
              }
            }
            if ($groupByDn.ContainsKey($dn) -and $groupByDn[$dn]) {
              $labels += (Format-GroupLabel -GroupObj $groupByDn[$dn])
            } else {
              $labels += $dn
            }
          }

          $cycles.Add([pscustomobject]@{
            CycleDepth = ($cycleDns.Count - 1)
            CyclePath  = ($labels -join " -> ")
            CycleDNs   = ($cycleDns -join " -> ")
            DetectedAt = (Get-Date).ToString("s")
          }) | Out-Null
        }
      }
      continue
    }

    if (-not $visited.Contains($childDn)) {
      DFS -CurrentDn $childDn -Depth ($Depth + 1)
    }
  }

  # pop
  $null = $inStack.Remove($CurrentDn)
  $path.RemoveAt($path.Count - 1)
}

# Prime cache with start
$groupByDn[$start.DistinguishedName] = $start
DFS -CurrentDn $start.DistinguishedName -Depth 1

Write-Host ("Start group: {0}" -f (Format-GroupLabel -GroupObj $start))
Write-Host ("MaxDepth: {0}" -f $MaxDepth)
Write-Host ("Cycles found: {0}" -f $cycles.Count)

if ($cycles.Count -gt 0) {
  $cycles | Sort-Object CycleDepth, CyclePath | Format-Table -AutoSize CycleDepth, CyclePath
}

if ($OutTsv) {
  Export-Tsv -Rows ($cycles | Sort-Object CycleDepth, CyclePath) -Path $OutTsv
  Write-Host ("Wrote TSV: {0}" -f $OutTsv)
}

if ($PassThru) {
  $cycles | Sort-Object CycleDepth, CyclePath
}