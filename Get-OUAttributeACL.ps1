<#
.SYNOPSIS
Reports attribute-level ACLs on an OU and (optionally) evaluates whether a given principal has effective access.

.DESCRIPTION
Reads the security descriptor (ACL) on a target OU and reports Access Control Entries (ACEs) that grant
ReadProperty and/or WriteProperty for specific attribute GUIDs.

Two usage modes are supported:

1) Principal mode (default when -Principal is provided)
   - For each requested attribute, determines whether the principal has effective access through:
     - direct ACEs on the OU
     - group membership (including nested groups)
     - inherited ACEs (where applicable)
   - Also lists the identities (users/groups) that grant access for each attribute so it is obvious which
     principals currently provide the permission.

2) Discovery mode (when -Principal is omitted)
   - For each requested attribute, lists all identities that have access at the OU and indicates whether
     each ACE is inherited.

Notes:
  - Requires RSAT Active Directory module.
  - This script reads permissions only. It does not modify ACLs.
  - Evaluation uses the OU DACL and performs SID expansion for identity references.
  - This script does not compute complex Windows "effective access" across multiple objects, denies,
    or Central Access Policies. It focuses on OU-level allow ACEs for attribute ReadProperty/WriteProperty.

.PARAMETER Principal
Optional. Identity of the user or group to evaluate. If omitted, all matching ACEs are reported.

.PARAMETER Domain
DNS name of the AD domain. Example: corp.example.com

.PARAMETER OU
OU distinguished-name fragment under the domain, or a full DN.
Examples:
  - "OU=Service Accounts,OU=Identity"
  - "OU=Service Accounts,OU=Identity,DC=corp,DC=example,DC=com"

.PARAMETER Attribute
Comma-separated list of attribute LDAP display names.
Example: "uid,uidNumber,gidNumber,unixHomeDirectory,loginShell"

.PARAMETER ReadOnly
Report only ReadProperty ACEs (and evaluate read access if -Principal is provided).

.PARAMETER ReadWrite
Report both ReadProperty and WriteProperty ACEs (and evaluate both if -Principal is provided).

.PARAMETER PreferGroup
Prefer resolving Principal as a group first (default).

.PARAMETER PreferUser
Prefer resolving Principal as a user first.

.PARAMETER IncludeInherited
Include inherited ACEs in the report and evaluation. Default is enabled.

.PARAMETER Raw
Output raw ACE objects (unformatted). Useful for further filtering/piping.

.EXAMPLE
# Evaluate whether a group has read/write access, and show which identities currently grant that access.
.\Get-OUAttributeAcl.ps1 `
  -Principal "ATTR_RW_UNIX_RFC2307" `
  -Domain "corp.example.com" `
  -OU "OU=Linux,OU=Service Accounts" `
  -Attribute "uid,uidNumber,gidNumber" `
  -ReadWrite

.EXAMPLE
# Discovery mode: list all identities with read access for an attribute on the OU.
.\Get-OUAttributeAcl.ps1 `
  -Domain "corp.example.com" `
  -OU "OU=Linux,OU=Service Accounts" `
  -Attribute "uidNumber" `
  -ReadOnly

.EXAMPLE
# Raw output for custom processing.
.\Get-OUAttributeAcl.ps1 `
  -Domain "corp.example.com" `
  -OU "OU=Linux,OU=Service Accounts" `
  -Attribute "uidNumber" `
  -ReadWrite `
  -Raw
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

  if ($OuInput -match '(?i)\bDC=') {
    return $OuInput
  }

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

  if ($Identity -match '^[^\\]+\\[^\\]+$') {
    $idToTry += $Identity.Split('\', 2)[1]
  }

  $idToTry = @($idToTry | Where-Object { $_ -and $_.Trim() -ne '' } | Select-Object -Unique)

  foreach ($id in $idToTry) {
    if ($Order -eq 'GroupFirst') {
      try {
        $g = Get-ADGroup -Server $Server -Identity $id -Properties objectSid, distinguishedName, samAccountName -ErrorAction Stop
        return [PSCustomObject]@{
          Type = 'Group'
          Name = $g.SamAccountName
          DN   = $g.DistinguishedName
          SID  = $g.SID
        }
      } catch { }

      try {
        $u = Get-ADUser -Server $Server -Identity $id -Properties objectSid, distinguishedName, samAccountName -ErrorAction Stop
        return [PSCustomObject]@{
          Type = 'User'
          Name = $u.SamAccountName
          DN   = $u.DistinguishedName
          SID  = $u.SID
        }
      } catch { }
    } else {
      try {
        $u = Get-ADUser -Server $Server -Identity $id -Properties objectSid, distinguishedName, samAccountName -ErrorAction Stop
        return [PSCustomObject]@{
          Type = 'User'
          Name = $u.SamAccountName
          DN   = $u.DistinguishedName
          SID  = $u.SID
        }
      } catch { }

      try {
        $g = Get-ADGroup -Server $Server -Identity $id -Properties objectSid, distinguishedName, samAccountName -ErrorAction Stop
        return [PSCustomObject]@{
          Type = 'Group'
          Name = $g.SamAccountName
          DN   = $g.DistinguishedName
          SID  = $g.SID
        }
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

function Try-ResolveSidToName {
  param(
    [Parameter(Mandatory = $true)][System.Security.Principal.SecurityIdentifier]$Sid,
    [Parameter(Mandatory = $true)][string]$Server
  )

  # Best-effort AD resolution. Returns a friendly string even if resolution fails.
  try {
    $o = Get-ADObject -Server $Server -Identity $Sid.Value -Properties objectClass, samAccountName -ErrorAction Stop
    if ($o.objectClass -contains 'group') {
      return "Group:$($o.samAccountName)"
    }
    if ($o.objectClass -contains 'user') {
      return "User:$($o.samAccountName)"
    }
    if ($o.samAccountName) {
      return "$($o.objectClass):$($o.samAccountName)"
    }
    return $Sid.Value
  } catch {
    return $Sid.Value
  }
}

function Get-PrincipalTokenSids {
  param(
    [Parameter(Mandatory = $true)][PSCustomObject]$PrincipalObj,
    [Parameter(Mandatory = $true)][string]$Server
  )

  # Returns SIDs that can grant access: the principal SID and (if user) group SIDs.
  $sidList = New-Object System.Collections.Generic.HashSet[string]
  $null = $sidList.Add($PrincipalObj.SID.Value)

  if ($PrincipalObj.Type -eq 'User') {
    $u = Get-ADUser -Server $Server -Identity $PrincipalObj.DN -Properties tokenGroups -ErrorAction Stop
    foreach ($tg in $u.tokenGroups) {
      $null = $sidList.Add(([System.Security.Principal.SecurityIdentifier]$tg).Value)
    }
  } elseif ($PrincipalObj.Type -eq 'Group') {
    # tokenGroups not available for groups. Expand nested group membership and add those group SIDs.
    $groupDns = @($PrincipalObj.DN)
    try {
      $nested = Get-ADGroupMember -Server $Server -Identity $PrincipalObj.DN -Recursive -ErrorAction Stop |
        Where-Object { $_.objectClass -eq 'group' } |
        Select-Object -ExpandProperty DistinguishedName
      $groupDns += $nested
    } catch { }

    $groupDns = @($groupDns | Select-Object -Unique)

    foreach ($dn in $groupDns) {
      try {
        $g = Get-ADGroup -Server $Server -Identity $dn -Properties objectSid -ErrorAction Stop
        $null = $sidList.Add($g.SID.Value)
      } catch { }
    }
  }

  return @($sidList)
}

function Get-AttributeAces {
  param(
    [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectorySecurity]$Acl,
    [Parameter(Mandatory = $true)][Guid]$AttrGuid,
    [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectoryRights[]]$RightsFilter,
    [Parameter(Mandatory = $true)][bool]$IncludeInherited
  )

  $rules = $Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
    Where-Object {
      $_ -is [System.DirectoryServices.ActiveDirectoryAccessRule] -and
      $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
      $_.ObjectType -eq $AttrGuid -and
      ($RightsFilter | Where-Object { $_ -band $_.ActiveDirectoryRights } | Measure-Object).Count -ge 0
    }

  # Filter rights explicitly - can include flags. Use bit test.
  $rules = $rules | Where-Object {
    $match = $false
    foreach ($r in $RightsFilter) {
      if (($_.ActiveDirectoryRights -band $r) -eq $r) { $match = $true; break }
    }
    $match
  }

  if (-not $IncludeInherited) {
    $rules = $rules | Where-Object { -not $_.IsInherited }
  }

  return @($rules)
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

# Validate OU exists
try {
  $null = Get-ADOrganizationalUnit -Server $Domain -Identity $ouDn -ErrorAction Stop
} catch {
  throw "OU not found or not accessible: $ouDn. Error: $($_.Exception.Message)"
}

# Parse attributes
$attrList = @(
  $Attribute.Split(',') |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -ne '' } |
    Select-Object -Unique
)

if ($attrList.Count -eq 0) {
  Throw-ArgError "Attribute list is empty."
}

$guidMap = Get-SchemaAttributeGuidMap -Server $Domain

$missing = @()
$resolved = @()
foreach ($a in $attrList) {
  if ($guidMap.ContainsKey($a)) {
    $resolved += [PSCustomObject]@{ Name = $a; Guid = $guidMap[$a] }
  } else {
    $missing += $a
  }
}

if ($missing.Count -gt 0) {
  throw "One or more attributes were not found in schema by lDAPDisplayName: $($missing -join ', ')"
}

$acl = Get-ObjectAcl -DistinguishedName $ouDn

$readRight  = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
$writeRight = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty

$rightsToCheck = @($readRight)
if ($ReadWrite) { $rightsToCheck = @($readRight, $writeRight) }

$principalObj = $null
$principalTokenSids = @()
if ($Principal -and $Principal.Trim() -ne '') {
  $principalObj = Resolve-Principal -Identity $Principal -Server $Domain -Order $resolveOrder
  $principalTokenSids = Get-PrincipalTokenSids -PrincipalObj $principalObj -Server $Domain
}

# Build report rows
$rows = @()

foreach ($attr in $resolved) {
  $aces = Get-AttributeAces -Acl $acl -AttrGuid $attr.Guid -RightsFilter $rightsToCheck -IncludeInherited:$IncludeInherited

  foreach ($ace in $aces) {
    $sid = [System.Security.Principal.SecurityIdentifier]$ace.IdentityReference
    $rows += [PSCustomObject]@{
      OU            = $ouDn
      AttributeName = $attr.Name
      AttributeGuid = $attr.Guid
      Rights        = $ace.ActiveDirectoryRights.ToString()
      IdentitySid   = $sid.Value
      IdentityName  = Try-ResolveSidToName -Sid $sid -Server $Domain
      IsInherited   = [bool]$ace.IsInherited
      Inheritance   = $ace.InheritanceType.ToString()
    }
  }
}

if ($Raw) {
  $rows
  return
}

Write-Host "Domain: $Domain"
Write-Host "OU DN:  $ouDn"
Write-Host "Attrs:  $($resolved.Name -join ', ')"
Write-Host "Mode:   $(if ($ReadWrite) { 'read-write (report read + write)' } else { 'read-only (report read)' })"
Write-Host "Incl inherited: $IncludeInherited"
Write-Host ""

if (-not $PrincipalObj) {
  if ($rows.Count -eq 0) {
    Write-Host "No matching attribute ACEs found on this OU for the requested attributes."
    return
  }

  $rows |
    Sort-Object AttributeName, Rights, IdentityName, IsInherited |
    Format-Table -AutoSize AttributeName, Rights, IdentityName, IdentitySid, IsInherited, Inheritance |
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

# Summarize effective access by attribute
$summary = @()
$grantDetails = @()

foreach ($attr in $resolved) {
  $aces = Get-AttributeAces -Acl $acl -AttrGuid $attr.Guid -RightsFilter $rightsToCheck -IncludeInherited:$IncludeInherited

  $readGranted = $false
  $writeGranted = $false

  $readGranting = New-Object System.Collections.Generic.List[string]
  $writeGranting = New-Object System.Collections.Generic.List[string]

  foreach ($ace in $aces) {
    $aceSid = ([System.Security.Principal.SecurityIdentifier]$ace.IdentityReference).Value
    $grantsPrincipal = $principalTokenSids -contains $aceSid
    if (-not $grantsPrincipal) { continue }

    $friendly = Try-ResolveSidToName -Sid ([System.Security.Principal.SecurityIdentifier]$ace.IdentityReference) -Server $Domain

    if ((($ace.ActiveDirectoryRights -band $readRight) -eq $readRight)) {
      $readGranted = $true
      $readGranting.Add($friendly) | Out-Null
    }
    if ($ReadWrite -and ((($ace.ActiveDirectoryRights -band $writeRight) -eq $writeRight))) {
      $writeGranted = $true
      $writeGranting.Add($friendly) | Out-Null
    }
  }

  # Also list who grants access in general (not just to the principal), for discovery in principal mode.
  $allRead = @()
  $allWrite = @()
  foreach ($ace in $aces) {
    $friendly = Try-ResolveSidToName -Sid ([System.Security.Principal.SecurityIdentifier]$ace.IdentityReference) -Server $Domain
    if ((($ace.ActiveDirectoryRights -band $readRight) -eq $readRight)) {
      $allRead += $friendly
    }
    if ($ReadWrite -and ((($ace.ActiveDirectoryRights -band $writeRight) -eq $writeRight))) {
      $allWrite += $friendly
    }
  }

  $summary += [PSCustomObject]@{
    AttributeName   = $attr.Name
    ReadGranted     = $readGranted
    WriteGranted    = $(if ($ReadWrite) { $writeGranted } else { $null })
    ReadVia         = $(if ($readGranting.Count -gt 0) { ($readGranting | Select-Object -Unique | Sort-Object) -join '; ' } else { '' })
    WriteVia        = $(if ($ReadWrite -and $writeGranting.Count -gt 0) { ($writeGranting | Select-Object -Unique | Sort-Object) -join '; ' } else { '' })
    OthersReadVia   = $(if ($allRead.Count -gt 0) { ($allRead | Select-Object -Unique | Sort-Object) -join '; ' } else { '' })
    OthersWriteVia  = $(if ($ReadWrite -and $allWrite.Count -gt 0) { ($allWrite | Select-Object -Unique | Sort-Object) -join '; ' } else { '' })
  }
}

$displayCols = @('AttributeName','ReadGranted','ReadVia','OthersReadVia')
if ($ReadWrite) { $displayCols = @('AttributeName','ReadGranted','WriteGranted','ReadVia','WriteVia','OthersReadVia','OthersWriteVia') }

$summary |
  Sort-Object AttributeName |
  Select-Object $displayCols |
  Format-Table -AutoSize |
  Out-String |
  ForEach-Object { Write-Host $_.TrimEnd() }

Write-Host ""
Write-Host "Detailed matching ACEs on OU (for requested attributes):"
Write-Host "------------------------------------------------------"

if ($rows.Count -eq 0) {
  Write-Host "No matching attribute ACEs found on this OU for the requested attributes."
  return
}

$rows |
  Sort-Object AttributeName, Rights, IdentityName, IsInherited |
  Format-Table -AutoSize AttributeName, Rights, IdentityName, IdentitySid, IsInherited, Inheritance |
  Out-String |
  ForEach-Object { Write-Host $_.TrimEnd() }