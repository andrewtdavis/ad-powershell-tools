<#
.SYNOPSIS
  Find circular (cyclic) nested group membership starting from a given group.

.DESCRIPTION
  Starting from a specified group (Name/sAMAccountName/DN) in a specific domain,
  enumerates nested group-to-group membership edges and detects circular paths
  such as:
     GroupA -> GroupB -> GroupC -> GroupA

  Cross-domain nested groups are resolved by deriving the group’s domain from
  its DN, then querying an appropriate DC in that domain.

  Reliability / scale features:
    - Retries membership enumeration across multiple DCs per domain.
    - Falls back to LDAP "member" ranged retrieval if Get-ADGroupMember (ADWS)
      faults with internal server errors.
    - Live cycle output and progress reporting.
    - MaxGroups safety cap.

.NOTES
  - Only group-to-group nesting is considered (users/computers ignored).
  - Membership is direct only; recursion is handled by this script so cycles can be detected.
  - Depth relates to group nesting depth, not users.

.PARAMETER Group
  Group identity: DistinguishedName (DN), sAMAccountName, or Name.

.PARAMETER Domain
  Domain FQDN (or a DC hostname) where the initial group lookup should occur
  when -Group is not a DN.

.PARAMETER MaxDepth
  Maximum nesting depth to explore (default: 200).

.PARAMETER MaxGroups
  Maximum unique groups to process before stopping (default: 500000).

.PARAMETER ProgressEvery
  Update progress after processing this many unique groups (default: 250).

.PARAMETER LiveOutput
  Emit each discovered cycle immediately to the console.

.PARAMETER NoSummary
  Suppress end-of-run summary table output.

.PARAMETER IncludeDistributionGroups
  Include distribution groups (GroupCategory=Distribution). By default, only
  security groups are traversed.

.PARAMETER OutTsv
  Optional path to write results as TSV.

.PARAMETER PassThru
  Output cycle objects to the pipeline (useful for further processing).

.EXAMPLE
  .\Find-ADGroupCircularMembership.ps1 `
    -Group "Business Impact Analysis Group" `
    -Domain "ucsfmedicalcenter.org" `
    -IncludeDistributionGroups `
    -MaxDepth 5000 `
    -MaxGroups 200000 `
    -ProgressEvery 500 `
    -LiveOutput

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$Group,

  [Parameter(Mandatory=$true)]
  [string]$Domain,

  [Parameter(Mandatory=$false)]
  [ValidateRange(1,5000)]
  [int]$MaxDepth = 200,

  [Parameter(Mandatory=$false)]
  [ValidateRange(1,5000000)]
  [int]$MaxGroups = 500000,

  [Parameter(Mandatory=$false)]
  [ValidateRange(1,1000000)]
  [int]$ProgressEvery = 250,

  [Parameter(Mandatory=$false)]
  [switch]$LiveOutput,

  [Parameter(Mandatory=$false)]
  [switch]$NoSummary,

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
      $dc = Get-ADDomainController -Discover -DomainName $d
      $map[$d.ToLowerInvariant()] = $dc.HostName
    }
  }

  return [pscustomobject]@{
    Forest = $forest
    DomainMap = $map
  }
}

function Get-ServerForDomain {
  param(
    [Parameter(Mandatory=$true)][string]$DomainName,
    [Parameter(Mandatory=$true)][hashtable]$DomainMap
  )

  $k = $DomainName.ToLowerInvariant()
  if ($DomainMap.ContainsKey($k) -and $DomainMap[$k]) { return $DomainMap[$k] }

  $dc = Get-ADDomainController -Discover -DomainName $DomainName
  return $dc.HostName
}

function Get-DomainControllersForDomain {
  param([Parameter(Mandatory=$true)][string]$DomainName)

  try {
    $dcs = Get-ADDomainController -Filter * -Server $DomainName -ErrorAction Stop |
      Where-Object { $_.HostName } |
      Select-Object -ExpandProperty HostName
    if ($dcs) { return @($dcs | Sort-Object -Unique) }
  } catch {}

  try {
    $dc = Get-ADDomainController -Discover -DomainName $DomainName -ErrorAction Stop
    if ($dc -and $dc.HostName) { return @($dc.HostName) }
  } catch {}

  return @()
}

function Resolve-Group {
  param(
    [Parameter(Mandatory=$true)][string]$GroupId,
    [Parameter(Mandatory=$true)][string]$DefaultDomain,
    [Parameter(Mandatory=$true)][hashtable]$DomainMap
  )

  # DN: derive domain from DN
  if ($GroupId -match '(?i)\bDC=') {
    $dom = Get-DomainFromDN -DistinguishedName $GroupId
    if (-not $dom) { throw "Could not derive domain from DN: $GroupId" }
    $srv = Get-ServerForDomain -DomainName $dom -DomainMap $DomainMap
    return Get-ADGroup -Identity $GroupId -Server $srv -Properties DistinguishedName,SamAccountName,Name,GroupCategory,GroupScope,ObjectGUID
  }

  # Otherwise search within provided domain
  $srv = Get-ServerForDomain -DomainName $DefaultDomain -DomainMap $DomainMap

  $g = Get-ADGroup -Identity $GroupId -Server $srv -ErrorAction SilentlyContinue -Properties DistinguishedName,SamAccountName,Name,GroupCategory,GroupScope,ObjectGUID
  if ($g) { return $g }

  $safe = $GroupId.Replace("'", "''")
  $g = Get-ADGroup -Server $srv -Filter "SamAccountName -eq '$safe' -or Name -eq '$safe'" -ErrorAction SilentlyContinue -Properties DistinguishedName,SamAccountName,Name,GroupCategory,GroupScope,ObjectGUID | Select-Object -First 1
  if ($g) { return $g }

  throw "Unable to resolve group '$GroupId' in domain '$DefaultDomain' (server $srv)."
}

function Get-DirectMemberDNsViaLdap {
  param(
    [Parameter(Mandatory=$true)][string]$GroupDN,
    [Parameter(Mandatory=$true)][string]$DomainName,
    [Parameter(Mandatory=$true)][string]$ServerHost
  )

  $baseDn = ($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','

  $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$ServerHost/$baseDn")
  $ds = New-Object System.DirectoryServices.DirectorySearcher($root)

  $escapedDn = Escape-LdapFilterValue -Value $GroupDN
  $ds.Filter = "(&(objectClass=group)(distinguishedName=$escapedDn))"
  $ds.PageSize = 1000
  $ds.SearchScope = "Subtree"

  $members = New-Object 'System.Collections.Generic.List[string]'

  # Try normal member first
  $ds.PropertiesToLoad.Clear()
  $null = $ds.PropertiesToLoad.Add("member")

  $res = $ds.FindOne()
  if (-not $res) { return @() }

  if ($res.Properties["member"] -and $res.Properties["member"].Count -gt 0) {
    foreach ($m in $res.Properties["member"]) { $members.Add([string]$m) }
    return @($members)
  }

  # Ranged retrieval for big groups
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

    if ($propName -match ';range=\d+-\*$') { break }

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
  try {
    $preferred = Get-ServerForDomain -DomainName $dom -DomainMap $DomainMap
    if ($preferred) { $dcCandidates += $preferred }
  } catch {}

  $dcCandidates += (Get-DomainControllersForDomain -DomainName $dom)
  $dcCandidates = @($dcCandidates | Where-Object { $_ } | Sort-Object -Unique)
  if (-not $dcCandidates.Count) { return @() }

  # 1) Try ADWS / Get-ADGroupMember across DC candidates
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
      continue
    }
  }

  # 2) Fallback: LDAP member attr (direct), then resolve group objects
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
  throw "Start group '$($start.Name)' is not a Security group. Use -IncludeDistributionGroups to traverse distribution groups."
}

# Caches
$groupByDn = @{}     # dn -> group object
$childrenByDn = @{}  # dn -> child dn array

function Get-ChildrenDnsCached {
  param([Parameter(Mandatory=$true)][object]$GroupObj)

  $dn = $GroupObj.DistinguishedName
  if ($childrenByDn.ContainsKey($dn)) { return @($childrenByDn[$dn]) }

  $kids = Get-NestedGroupMembers -GroupObj $GroupObj -DomainMap $domainMap -AllowDistribution $allowDist
  foreach ($k in $kids) { $groupByDn[$k.DistinguishedName] = $k }
  $childrenByDn[$dn] = @($kids | ForEach-Object { $_.DistinguishedName })
  return @($childrenByDn[$dn])
}

# Cycle detection state
$visited = New-Object 'System.Collections.Generic.HashSet[string]'
$inStack = New-Object 'System.Collections.Generic.HashSet[string]'
$path = New-Object 'System.Collections.Generic.List[string]'

$cycleKeys = New-Object 'System.Collections.Generic.HashSet[string]'
$cycles = New-Object 'System.Collections.Generic.List[object]'

# Shared stats (script scope so DFS updates persist)
$script:groupsProcessed = 0
$script:edgesProcessed  = 0
$script:stopRequested   = $false

# Groups member-of other groups (in-degree > 0), and parent groups that contain other groups
$script:inDegree = @{}  # childDN -> count
$script:parentsSeen = New-Object 'System.Collections.Generic.HashSet[string]'

function Normalize-CycleKey {
  param([Parameter(Mandatory=$true)][string[]]$CycleDns)
  $core = $CycleDns[0..($CycleDns.Count-2)]
  $min = $core | Sort-Object | Select-Object -First 1
  $idx = [Array]::IndexOf($core, $min)
  if ($idx -lt 0) { $idx = 0 }

  $rot = @()
  for ($i=0; $i -lt $core.Count; $i++) {
    $rot += $core[($idx + $i) % $core.Count]
  }
  $rot += $rot[0]
  return ($rot -join " -> ")
}

function DFS {
  param(
    [Parameter(Mandatory=$true)][string]$CurrentDn,
    [Parameter(Mandatory=$true)][int]$Depth
  )

  if ($script:stopRequested) { return }
  if ($Depth -gt $MaxDepth) { return }

  $null = $visited.Add($CurrentDn)
  $null = $inStack.Add($CurrentDn)
  $path.Add($CurrentDn) | Out-Null

  $script:groupsProcessed++
  if ($script:groupsProcessed -ge $MaxGroups) {
    $script:stopRequested = $true
    return
  }

  if (($script:groupsProcessed % $ProgressEvery) -eq 0) {
    Write-Progress -Activity "Scanning group nesting for cycles" `
      -Status ("Processed {0} groups; resolved {1}; edges {2}; member-of {3}; cycles {4}; depth {5}" -f $script:groupsProcessed, $groupByDn.Count, $script:edgesProcessed, $script:inDegree.Count, $cycles.Count, $Depth) `
      -PercentComplete 0
  }

  if (-not $groupByDn.ContainsKey($CurrentDn)) {
    $dom = Get-DomainFromDN -DistinguishedName $CurrentDn
    if ($dom) {
      try {
        $srv = Get-ServerForDomain -DomainName $dom -DomainMap $domainMap
        $groupByDn[$CurrentDn] = Get-ADGroup -Identity $CurrentDn -Server $srv -Properties DistinguishedName,SamAccountName,Name,GroupCategory,GroupScope,ObjectGUID
      } catch {}
    }
  }

  $curObj = $groupByDn[$CurrentDn]
  $childDns = @()
  if ($curObj) {
    $childDns = @(Get-ChildrenDnsCached -GroupObj $curObj)
  }
  $childDns = @($childDns)

  $script:edgesProcessed += $childDns.Count

  # Update stats: in-degree and parent sets
  foreach ($__c in $childDns) {
    if ($__c) {
      $script:parentsSeen.Add($CurrentDn) | Out-Null
      if ($script:inDegree.ContainsKey($__c)) { $script:inDegree[$__c] = [int]$script:inDegree[$__c] + 1 }
      else { $script:inDegree[$__c] = 1 }
    }
  }

  foreach ($childDn in $childDns) {
    if ($script:stopRequested) { break }

    if ($inStack.Contains($childDn)) {
      $startIdx = $path.IndexOf($childDn)
      if ($startIdx -ge 0) {
        $cycleDns = @()
        for ($i=$startIdx; $i -lt $path.Count; $i++) { $cycleDns += $path[$i] }
        $cycleDns += $childDn

        $key = Normalize-CycleKey -CycleDns $cycleDns
        if ($cycleKeys.Add($key)) {
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

          $cycleObj = [pscustomobject]@{
            CycleDepth = ($cycleDns.Count - 1)
            CyclePath  = ($labels -join " -> ")
            CycleDNs   = ($cycleDns -join " -> ")
            DetectedAt = (Get-Date).ToString("s")
          }

          $cycles.Add($cycleObj) | Out-Null

          if ($LiveOutput) {
            $cycleObj | Format-List CycleDepth, CyclePath, DetectedAt
            Write-Host "----"
          }

          if ($PassThru) { $cycleObj }
        }
      }
      continue
    }

    if (-not $visited.Contains($childDn)) {
      DFS -CurrentDn $childDn -Depth ($Depth + 1)
    }
  }

  $null = $inStack.Remove($CurrentDn)
  $path.RemoveAt($path.Count - 1)
}

# Prime cache with start group
$groupByDn[$start.DistinguishedName] = $start

DFS -CurrentDn $start.DistinguishedName -Depth 1

Write-Progress -Activity "Scanning group nesting for cycles" -Completed

Write-Host ("Start group: {0}" -f (Format-GroupLabel -GroupObj $start))
Write-Host ("MaxDepth: {0} | MaxGroups: {1} | ProgressEvery: {2}" -f $MaxDepth, $MaxGroups, $ProgressEvery)
Write-Host ("Processed groups: {0} | resolved groups: {1} | edges: {2} | groups member-of: {3}" -f $script:groupsProcessed, $groupByDn.Count, $script:edgesProcessed, $script:inDegree.Count)
Write-Host ("Groups that contain other groups: {0}" -f $script:parentsSeen.Count)

if ($script:stopRequested) {
  Write-Warning ("Stopped early after reaching MaxGroups ({0}). Increase -MaxGroups if you intend to scan further." -f $MaxGroups)
}

Write-Host ("Cycles found: {0}" -f $cycles.Count)

if (-not $NoSummary -and $cycles.Count -gt 0) {
  $cycles | Sort-Object CycleDepth, CyclePath | Format-Table -AutoSize CycleDepth, CyclePath
}

if ($OutTsv) {
  Export-Tsv -Rows ($cycles | Sort-Object CycleDepth, CyclePath) -Path $OutTsv
  Write-Host ("Wrote TSV: {0}" -f $OutTsv)
}
