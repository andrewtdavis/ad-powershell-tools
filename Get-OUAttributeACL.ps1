<#
.SYNOPSIS
Reports attribute-level ACLs on an OU, including well-known identities, common RID-based domain groups,
and broader rights that imply attribute read/write access. Unknown domain SIDs are annotated with the base domain SID.

.DESCRIPTION
Reads the DACL on a target OU and reports allow ACEs that can result in effective ReadProperty and/or WriteProperty
access for specific attributes.

Enhancements in this revision:
  - Adds BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
  - When a SID does not resolve, annotates domain SIDs (S-1-5-21-...-RID) with the base domain SID:
      Example: "S-1-5-21-A-B-C-1234 [domainSid=S-1-5-21-A-B-C rid=1234]"
    This is helpful when ACLs contain orphaned SIDs from removed trusts or decommissioned domains.

See previous header content for full behavior.

.PARAMETER Principal
Optional. Identity of the user or group to evaluate.

.PARAMETER Domain
DNS name of the AD domain.

.PARAMETER OU
OU DN fragment or full DN.

.PARAMETER Attribute
Comma-separated list of attribute LDAP display names.

.PARAMETER ReadOnly
Report and evaluate ReadProperty only.

.PARAMETER ReadWrite
Report and evaluate ReadProperty and WriteProperty.

.PARAMETER PreferGroup
Prefer resolving Principal as a group first.

.PARAMETER PreferUser
Prefer resolving Principal as a user first.

.PARAMETER IncludeInherited
Include inherited ACEs.

.PARAMETER IncludeDeny
Include deny ACEs in output (deny not used for full effective access computation).

.PARAMETER IncludeGrantCapable
Include WriteDacl/WriteOwner as "CanGrant".

.PARAMETER Raw
Output objects rather than formatted tables.

.EXAMPLE
.\Get-OuAttributeAcl.ps1 -Domain test.com -OU "OU=Accounts,OU=Gladstone" -Attribute "uid,uidNumber,gidNumber" -ReadWrite
#>

[CmdletBinding(DefaultParameterSetName = 'ReadOnly')]
param(
  [Parameter(Mandatory = $false)]
  [string]$Principal,

  [Parameter(Mandatory = $true)]
  [string]$Domain,

  [Parameter(Mandatory = $true)]
  [string]$OU,

  [Parameter(Mandatory = $true)]
  [string]$Attribute,

  [Parameter(Mandatory = $true, ParameterSetName = 'ReadOnly')]
  [switch]$ReadOnly,

  [Parameter(Mandatory = $true, ParameterSetName = 'ReadWrite')]
  [switch]$ReadWrite,

  [Parameter(ParameterSetName = 'ReadOnly')]
  [Parameter(ParameterSetName = 'ReadWrite')]
  [switch]$PreferGroup,

  [Parameter(ParameterSetName = 'ReadOnly')]
  [Parameter(ParameterSetName = 'ReadWrite')]
  [switch]$PreferUser,

  [switch]$IncludeInherited = $true,

  [switch]$IncludeDeny,

  [switch]$IncludeGrantCapable = $true,

  [switch]$Raw
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Throw-ArgError {
  param([string]$Message)
  throw [System.ArgumentException]::new($Message)
}

function Ensure-ActiveDirectoryModule {
  if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Throw-ArgError "ActiveDirectory module not found. Install RSAT: Active Directory Domain Services and Lightweight Directory Services tools."
  }
  Import-Module ActiveDirectory -ErrorAction Stop
}

function Get-DomainDnFromDns {
  param([Parameter(Mandatory = $true)][string]$DnsName)

  $parts = @($DnsName.Split('.') | Where-Object { $_ -and $_.Trim() -ne '' })
  if ($parts.Count -lt 2) {
    Throw-ArgError "Domain must be a DNS name like corp.example.com. Got: $DnsName"
  }

  ($parts | ForEach-Object { "DC=$_" }) -join ','
}

function Normalize-OuDn {
  param(
    [Parameter(Mandatory = $true)][string]$OuInput,
    [Parameter(Mandatory = $true)][string]$DomainDn
  )

  if ($OuInput -match '(?i)\bDC=') { return $OuInput }

  $trimmed = $OuInput.Trim().TrimEnd(',')
  if (-not ($trimmed -match '(?i)^\s*OU=')) {
    Throw-ArgError "OU must start with OU= (unless a full DN is provided). Got: $OuInput"
  }

  return "$trimmed,$DomainDn"
}

function Resolve-Principal {
  param(
    [Parameter(Mandatory = $true)][string]$Identity,
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][ValidateSet('GroupFirst','UserFirst')][string]$Order
  )

  $idToTry = @($Identity)
  if ($Identity -match '^[^\\]+\\[^\\]+$') { $idToTry += $Identity.Split('\', 2)[1] }
  $idToTry = @($idToTry | Where-Object { $_ -and $_.Trim() -ne '' } | Select-Object -Unique)

  foreach ($id in $idToTry) {
    if ($Order -eq 'GroupFirst') {
      try {
        $g = Get-ADGroup -Server $Server -Identity $id -Properties objectSid, distinguishedName, samAccountName -ErrorAction Stop
        return [PSCustomObject]@{ Type = 'Group'; Name = $g.SamAccountName; DN = $g.DistinguishedName; SID = $g.SID }
      } catch { }

      try {
        $u = Get-ADUser -Server $Server -Identity $id -Properties objectSid, distinguishedName, samAccountName -ErrorAction Stop
        return [PSCustomObject]@{ Type = 'User'; Name = $u.SamAccountName; DN = $u.DistinguishedName; SID = $u.SID }
      } catch { }
    } else {
      try {
        $u = Get-ADUser -Server $Server -Identity $id -Properties objectSid, distinguishedName, samAccountName -ErrorAction Stop
        return [PSCustomObject]@{ Type = 'User'; Name = $u.SamAccountName; DN = $u.DistinguishedName; SID = $u.SID }
      } catch { }

      try {
        $g = Get-ADGroup -Server $Server -Identity $id -Properties objectSid, distinguishedName, samAccountName -ErrorAction Stop
        return [PSCustomObject]@{ Type = 'Group'; Name = $g.SamAccountName; DN = $g.DistinguishedName; SID = $g.SID }
      } catch { }
    }
  }

  Throw-ArgError "Unable to resolve Principal to an AD user or group on domain '$Server': $Identity"
}

function Get-SchemaAttributeGuidMap {
  param([Parameter(Mandatory = $true)][string]$Server)

  $rootDse = Get-ADRootDSE -Server $Server
  $schemaNc = $rootDse.schemaNamingContext

  $map = @{}
  $attrs = Get-ADObject -Server $Server `
    -SearchBase $schemaNc `
    -LDAPFilter '(objectClass=attributeSchema)' `
    -Properties lDAPDisplayName, schemaIDGUID

  foreach ($a in $attrs) {
    if (-not $a.lDAPDisplayName) { continue }
    if (-not $a.schemaIDGUID) { continue }
    $map[$a.lDAPDisplayName] = [Guid]$a.schemaIDGUID
  }

  return $map
}

function Get-ObjectAcl {
  param([Parameter(Mandatory = $true)][string]$DistinguishedName)

  $path = "AD:$DistinguishedName"
  try {
    Get-Acl -Path $path -ErrorAction Stop
  } catch {
    throw "Failed to read ACL from $path. Error: $($_.Exception.Message)"
  }
}

function Get-KnownSidLabelMap {
  param([Parameter(Mandatory = $true)][string]$Server)

  $map = @{
    'S-1-1-0'      = 'Everyone'
    'S-1-5-11'     = 'Authenticated Users'
    'S-1-5-10'     = 'SELF'
    'S-1-5-18'     = 'LOCAL SYSTEM'
    'S-1-5-32-544' = 'BUILTIN\Administrators'
    'S-1-5-32-545' = 'BUILTIN\Users'
    'S-1-5-32-546' = 'BUILTIN\Guests'
    'S-1-5-32-548' = 'BUILTIN\Account Operators'
    'S-1-5-32-549' = 'BUILTIN\Server Operators'
    'S-1-5-32-550' = 'BUILTIN\Print Operators'
    'S-1-5-32-551' = 'BUILTIN\Backup Operators'
    'S-1-5-32-554' = 'BUILTIN\Pre-Windows 2000 Compatible Access'
  }

  $domainSid = $null
  $forestRootSid = $null

  try {
    $d = Get-ADDomain -Server $Server -ErrorAction Stop
    $domainSid = $d.DomainSID.Value
  } catch { }

  try {
    $f = Get-ADForest -Server $Server -ErrorAction Stop
    if ($f.RootDomain) {
      $rd = Get-ADDomain -Server $f.RootDomain -ErrorAction Stop
      $forestRootSid = $rd.DomainSID.Value
    }
  } catch { }

  if ($domainSid) {
    $map["$domainSid-512"] = 'Domain Admins (RID 512)'
    $map["$domainSid-513"] = 'Domain Users (RID 513)'
    $map["$domainSid-514"] = 'Domain Guests (RID 514)'
    $map["$domainSid-515"] = 'Domain Computers (RID 515)'
    $map["$domainSid-516"] = 'Domain Controllers (RID 516)'
    $map["$domainSid-517"] = 'Cert Publishers (RID 517)'
    $map["$domainSid-520"] = 'Group Policy Creator Owners (RID 520)'
  }

  if ($forestRootSid) {
    $map["$forestRootSid-518"] = 'Schema Admins (RID 518) [forest root]'
    $map["$forestRootSid-519"] = 'Enterprise Admins (RID 519) [forest root]'
  }

  return $map
}

function Get-DomainSidAnnotation {
  param([Parameter(Mandatory = $true)][string]$SidString)

  # Returns a short annotation string for S-1-5-21-...-RID SIDs, otherwise $null.
  if ($SidString -notmatch '^S-1-5-21-(\d+)-(\d+)-(\d+)-(\d+)$') {
    return $null
  }

  $parts = $SidString.Split('-')
  $rid = $parts[-1]
  $domainSid = ($parts[0..($parts.Length - 2)] -join '-')
  return "domainSid=$domainSid rid=$rid"
}

function Resolve-SidFriendly {
  param(
    [Parameter(Mandatory = $true)][System.Security.Principal.SecurityIdentifier]$Sid,
    [Parameter(Mandatory = $true)][hashtable]$KnownSidLabels
  )

  $sidStr = $Sid.Value

  if ($KnownSidLabels.ContainsKey($sidStr)) {
    return $KnownSidLabels[$sidStr]
  }

  try {
    return ($Sid.Translate([System.Security.Principal.NTAccount])).Value
  } catch {
    $ann = Get-DomainSidAnnotation -SidString $sidStr
    if ($ann) {
      return "$sidStr [$ann]"
    }
    return $sidStr
  }
}

function Get-PrincipalTokenSids {
  param(
    [Parameter(Mandatory = $true)][PSCustomObject]$PrincipalObj,
    [Parameter(Mandatory = $true)][string]$Server
  )

  $set = New-Object System.Collections.Generic.HashSet[string]
  $null = $set.Add($PrincipalObj.SID.Value)

  if ($PrincipalObj.Type -eq 'User') {
    $u = Get-ADUser -Server $Server -Identity $PrincipalObj.DN -Properties tokenGroups -ErrorAction Stop
    foreach ($tg in $u.tokenGroups) {
      $null = $set.Add(([System.Security.Principal.SecurityIdentifier]$tg).Value)
    }
  } else {
    $dns = @($PrincipalObj.DN)
    try {
      $nestedDns = Get-ADGroupMember -Server $Server -Identity $PrincipalObj.DN -Recursive -ErrorAction Stop |
        Where-Object { $_.objectClass -eq 'group' } |
        Select-Object -ExpandProperty DistinguishedName
      $dns += $nestedDns
    } catch { }

    $dns = @($dns | Select-Object -Unique)
    foreach ($dn in $dns) {
      try {
        $g = Get-ADGroup -Server $Server -Identity $dn -Properties objectSid -ErrorAction Stop
        $null = $set.Add($g.SID.Value)
      } catch { }
    }
  }

  return @($set)
}

function Get-RelevantAcesForAttribute {
  param(
    [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectorySecurity]$Acl,
    [Parameter(Mandatory = $true)][Guid]$AttrGuid,
    [Parameter(Mandatory = $true)][bool]$IncludeInherited,
    [Parameter(Mandatory = $true)][bool]$IncludeDeny
  )

  $rules = $Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
    Where-Object { $_ -is [System.DirectoryServices.ActiveDirectoryAccessRule] }

  if (-not $IncludeInherited) { $rules = $rules | Where-Object { -not $_.IsInherited } }
  if (-not $IncludeDeny) { $rules = $rules | Where-Object { $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow } }

  $empty = [Guid]::Empty
  $rules = $rules | Where-Object { $_.ObjectType -eq $AttrGuid -or $_.ObjectType -eq $empty }

  return @($rules)
}

function Classify-AceForAccess {
  param(
    [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectoryAccessRule]$Ace,
    [Parameter(Mandatory = $true)][Guid]$AttrGuid,
    [Parameter(Mandatory = $true)][bool]$WantRead,
    [Parameter(Mandatory = $true)][bool]$WantWrite,
    [Parameter(Mandatory = $true)][bool]$IncludeGrantCapable
  )

  $rights = $Ace.ActiveDirectoryRights

  $readProperty  = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
  $writeProperty = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
  $genericRead   = [System.DirectoryServices.ActiveDirectoryRights]::GenericRead
  $genericWrite  = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
  $genericAll    = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
  $writeDacl     = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
  $writeOwner    = [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner

  $targetsAllProps = ($Ace.ObjectType -eq [Guid]::Empty)
  $targetsAttr     = ($Ace.ObjectType -eq $AttrGuid)

  $providesRead = $false
  $providesWrite = $false
  $canGrant = $false

  if ($WantRead) {
    if ((($rights -band $genericAll) -eq $genericAll) -or (($rights -band $genericRead) -eq $genericRead)) {
      $providesRead = $true
    } elseif ((($rights -band $readProperty) -eq $readProperty) -and ($targetsAttr -or $targetsAllProps)) {
      $providesRead = $true
    }
  }

  if ($WantWrite) {
    if ((($rights -band $genericAll) -eq $genericAll) -or (($rights -band $genericWrite) -eq $genericWrite)) {
      $providesWrite = $true
    } elseif ((($rights -band $writeProperty) -eq $writeProperty) -and ($targetsAttr -or $targetsAllProps)) {
      $providesWrite = $true
    }
  }

  if ($IncludeGrantCapable) {
    if ((($rights -band $writeDacl) -eq $writeDacl) -or (($rights -band $writeOwner) -eq $writeOwner)) {
      $canGrant = $true
    }
  }

  return [PSCustomObject]@{
    ProvidesRead  = $providesRead
    ProvidesWrite = $providesWrite
    CanGrant      = $canGrant
  }
}

# Main
Ensure-ActiveDirectoryModule

if ($PreferGroup -and $PreferUser) {
  Throw-ArgError "Specify only one of -PreferGroup or -PreferUser."
}

$resolveOrder = 'GroupFirst'
if ($PreferUser) { $resolveOrder = 'UserFirst' }

$domainDn = Get-DomainDnFromDns -DnsName $Domain
$ouDn = Normalize-OuDn -OuInput $OU -DomainDn $domainDn

try {
  $null = Get-ADOrganizationalUnit -Server $Domain -Identity $ouDn -ErrorAction Stop
} catch {
  throw "OU not found or not accessible: $ouDn. Error: $($_.Exception.Message)"
}

$attrList = @(
  $Attribute.Split(',') |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -ne '' } |
    Select-Object -Unique
)
if ($attrList.Count -eq 0) { Throw-ArgError "Attribute list is empty." }

$guidMap = Get-SchemaAttributeGuidMap -Server $Domain

$missing = @()
$resolved = @()
foreach ($a in $attrList) {
  if ($guidMap.ContainsKey($a)) { $resolved += [PSCustomObject]@{ Name = $a; Guid = $guidMap[$a] } }
  else { $missing += $a }
}
if ($missing.Count -gt 0) {
  throw "One or more attributes were not found in schema by lDAPDisplayName: $($missing -join ', ')"
}

$acl = Get-ObjectAcl -DistinguishedName $ouDn
$knownSidLabels = Get-KnownSidLabelMap -Server $Domain

$wantRead = $true
$wantWrite = $false
if ($ReadWrite) { $wantWrite = $true }

$principalObj = $null
$principalTokenSids = @()
if ($Principal -and $Principal.Trim() -ne '') {
  $principalObj = Resolve-Principal -Identity $Principal -Server $Domain -Order $resolveOrder
  $principalTokenSids = Get-PrincipalTokenSids -PrincipalObj $principalObj -Server $Domain
}

$rows = @()

foreach ($attr in $resolved) {
  $aces = Get-RelevantAcesForAttribute -Acl $acl -AttrGuid $attr.Guid -IncludeInherited:$IncludeInherited -IncludeDeny:$IncludeDeny

  foreach ($ace in $aces) {
    $sid = [System.Security.Principal.SecurityIdentifier]$ace.IdentityReference
    $friendly = Resolve-SidFriendly -Sid $sid -KnownSidLabels $knownSidLabels
    $class = Classify-AceForAccess -Ace $ace -AttrGuid $attr.Guid -WantRead:$wantRead -WantWrite:$wantWrite -IncludeGrantCapable:$IncludeGrantCapable

    $grantTypes = @()
    if ($class.ProvidesRead) { $grantTypes += 'Read' }
    if ($class.ProvidesWrite) { $grantTypes += 'Write' }
    if ($class.CanGrant) { $grantTypes += 'CanGrant' }
    if ($grantTypes.Count -eq 0) { continue }

    $targets = if ($ace.ObjectType -eq [Guid]::Empty) { 'AllProperties' } else { 'AttributeOnly' }

    $rows += [PSCustomObject]@{
      OU              = $ouDn
      AttributeName   = $attr.Name
      AttributeGuid   = $attr.Guid
      AppliesTo       = $targets
      GrantTypes      = ($grantTypes -join ',')
      AccessType      = $ace.AccessControlType.ToString()
      Rights          = $ace.ActiveDirectoryRights.ToString()
      IdentityName    = $friendly
      IdentitySid     = $sid.Value
      IsInherited     = [bool]$ace.IsInherited
      InheritanceType = $ace.InheritanceType.ToString()
    }
  }
}

if ($Raw) { $rows; return }

Write-Host "Domain: $Domain"
Write-Host "OU DN:  $ouDn"
Write-Host "Attrs:  $($resolved.Name -join ', ')"
Write-Host "Mode:   $(if ($ReadWrite) { 'read-write (read + write + grant-capable)' } else { 'read-only (read + grant-capable)' })"
Write-Host "Incl inherited: $IncludeInherited"
Write-Host "Incl deny:      $IncludeDeny"
Write-Host "Incl can-grant: $IncludeGrantCapable"
Write-Host ""

if (-not $principalObj) {
  if ($rows.Count -eq 0) {
    Write-Host "No relevant ACEs found for the requested attributes on this OU (under the selected filters)."
    return
  }

  $rows |
    Sort-Object AttributeName, GrantTypes, IdentityName, IsInherited |
    Format-Table -AutoSize AttributeName, GrantTypes, AppliesTo, AccessType, IdentityName, IdentitySid, IsInherited, Rights |
    Out-String |
    ForEach-Object { Write-Host $_.TrimEnd() }

  return
}

Write-Host "Principal input: $Principal"
Write-Host "Resolved type:   $($principalObj.Type)"
Write-Host "Resolved name:   $($principalObj.Name)"
Write-Host "Resolved DN:     $($principalObj.DN)"
Write-Host "Resolved SID:    $($principalObj.SID.Value)"
Write-Host ""

$summary = @()

foreach ($attr in $resolved) {
  $attrRows = $rows | Where-Object { $_.AttributeName -eq $attr.Name }

  $readGranted = $false
  $writeGranted = $false
  $grantCapable = $false

  $readVia = @()
  $writeVia = @()
  $grantVia = @()

  foreach ($r in $attrRows) {
    if (-not ($principalTokenSids -contains $r.IdentitySid)) { continue }
    $gts = $r.GrantTypes.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

    if ($gts -contains 'Read') { $readGranted = $true; $readVia += $r.IdentityName }
    if ($gts -contains 'Write') { $writeGranted = $true; $writeVia += $r.IdentityName }
    if ($gts -contains 'CanGrant') { $grantCapable = $true; $grantVia += $r.IdentityName }
  }

  $othersRead = @()
  $othersWrite = @()
  $othersGrant = @()
  foreach ($r in $attrRows) {
    $gts = $r.GrantTypes.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    if ($gts -contains 'Read') { $othersRead += $r.IdentityName }
    if ($gts -contains 'Write') { $othersWrite += $r.IdentityName }
    if ($gts -contains 'CanGrant') { $othersGrant += $r.IdentityName }
  }

  $summary += [PSCustomObject]@{
    AttributeName    = $attr.Name
    ReadGranted      = $readGranted
    WriteGranted     = $(if ($ReadWrite) { $writeGranted } else { $null })
    CanGrantAcl      = $(if ($IncludeGrantCapable) { $grantCapable } else { $null })
    ReadVia          = ($(($readVia | Select-Object -Unique | Sort-Object) -join '; '))
    WriteVia         = ($(($writeVia | Select-Object -Unique | Sort-Object) -join '; '))
    CanGrantVia      = ($(($grantVia | Select-Object -Unique | Sort-Object) -join '; '))
    OthersReadVia    = ($(($othersRead | Select-Object -Unique | Sort-Object) -join '; '))
    OthersWriteVia   = ($(($othersWrite | Select-Object -Unique | Sort-Object) -join '; '))
    OthersCanGrant   = ($(($othersGrant | Select-Object -Unique | Sort-Object) -join '; '))
  }
}

$cols = @('AttributeName','ReadGranted','ReadVia','OthersReadVia')
if ($ReadWrite) {
  $cols = @('AttributeName','ReadGranted','WriteGranted','CanGrantAcl','ReadVia','WriteVia','CanGrantVia','OthersReadVia','OthersWriteVia','OthersCanGrant')
} elseif ($IncludeGrantCapable) {
  $cols = @('AttributeName','ReadGranted','CanGrantAcl','ReadVia','CanGrantVia','OthersReadVia','OthersCanGrant')
}

$summary |
  Sort-Object AttributeName |
  Select-Object $cols |
  Format-Table -AutoSize |
  Out-String |
  ForEach-Object { Write-Host $_.TrimEnd() }

Write-Host ""
Write-Host "Detailed relevant ACEs on OU (filtered to requested attributes):"
Write-Host "--------------------------------------------------------------"

if ($rows.Count -eq 0) {
  Write-Host "No relevant ACEs found for the requested attributes on this OU (under the selected filters)."
  return
}

$rows |
  Sort-Object AttributeName, GrantTypes, IdentityName, IsInherited |
  Format-Table -AutoSize AttributeName, GrantTypes, AppliesTo, AccessType, IdentityName, IdentitySid, IsInherited, Rights |
  Out-String |
  ForEach-Object { Write-Host $_.TrimEnd() }