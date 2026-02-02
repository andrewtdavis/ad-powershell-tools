<#
.SYNOPSIS
Delegates read-only or read-write permissions for specific attributes on an OU to a user or group, with an interactive confirmation gate.

.DESCRIPTION
Builds a change plan (the ACEs that will be added) for a target OU so a specified principal (user or group) can read
and optionally write a specified list of attributes (for example RFC2307 attributes).

The script grants permissions on:
  - the OU object itself
  - all descendant objects (via inheritance)

Permissions granted:
  - ReadProperty on specified attributes (both modes)
  - WriteProperty on specified attributes (only with -ReadWrite)

Before making changes, the script prints the exact ACEs that will be added and prompts for confirmation.
To skip prompting (batch execution), use -Force or run with -Confirm:$false.

Notes:
  - Requires the ActiveDirectory module (RSAT).
  - Must be run by an account that can modify permissions on the target OU.
  - Attribute names are resolved to schema attribute GUIDs using the domain schema.
  - Existing matching ACEs are detected to avoid duplicates.

.PARAMETER Principal
Identity of the user or group to delegate to.
Recommended formats:
  - SamAccountName
  - Distinguished Name
  - UPN (for users)
  - DOMAIN\Name (best-effort)

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
Grant only read permission for the specified attributes.

.PARAMETER ReadWrite
Grant read and write permission for the specified attributes.

.PARAMETER PreferGroup
Prefer resolving Principal as a group first (default).

.PARAMETER PreferUser
Prefer resolving Principal as a user first.

.PARAMETER DryRun
Show intended changes but do not modify ACLs.

.PARAMETER Force
Skip the interactive confirmation prompt and proceed with changes.
Equivalent to common "batch" behavior.

.EXAMPLE
.\Set-OuAttributeAcl.ps1 `
  -Principal "ATTR_RW_UNIX_RFC2307" `
  -Domain "corp.example.com" `
  -OU "OU=Linux,OU=Service Accounts" `
  -Attribute "uid,uidNumber,gidNumber,unixHomeDirectory,loginShell" `
  -ReadWrite

.EXAMPLE
.\Set-OuAttributeAcl.ps1 `
  -Principal "ATTR_RW_UCSF02NUMBER" `
  -Domain "gladstone.internal" `
  -OU "OU=UCSF Identity Sync Test,OU=Process and Testing,OU=Accounts,OU=Gladstone" `
  -Attribute "gladstone-UCSFID" `
  -ReadWrite `
  -DryRun

.EXAMPLE
.\Set-OuAttributeAcl.ps1 `
  -Principal "ATTR_RW_UNIX_RFC2307" `
  -Domain "corp.example.com" `
  -OU "OU=Linux,OU=Service Accounts" `
  -Attribute "uidNumber" `
  -ReadWrite `
  -Force
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'ReadOnly')]
param(
  [Parameter(Mandatory = $true)]
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

  [switch]$DryRun,

  [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info {
  param([string]$Message)
  Write-Host $Message
}

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

  if ($Identity -match '^[^\\]+\$begin:math:display$\^\\$end:math:display$+$') {
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
    return Get-Acl -Path $path -ErrorAction Stop
  } catch {
    throw "Failed to read ACL from $path. Error: $($_.Exception.Message)"
  }
}

function Set-ObjectAcl {
  param(
    [Parameter(Mandatory = $true)][string]$DistinguishedName,
    [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectorySecurity]$Acl
  )

  $path = "AD:$DistinguishedName"
  if ($DryRun) {
    Write-Info "DryRun: would set ACL on $path"
    return
  }

  if ($PSCmdlet.ShouldProcess($path, "Set-Acl")) {
    try {
      Set-Acl -Path $path -AclObject $Acl -ErrorAction Stop
    } catch {
      throw "Failed to set ACL on $path. Error: $($_.Exception.Message)"
    }
  }
}

function New-AttributeRule {
  param(
    [Parameter(Mandatory = $true)][System.Security.Principal.SecurityIdentifier]$Sid,
    [Parameter(Mandatory = $true)][Guid]$AttributeGuid,
    [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectoryRights]$Rights
  )

  $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
  $accessType = [System.Security.AccessControl.AccessControlType]::Allow

  New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    -ArgumentList $Sid, $Rights, $accessType, $AttributeGuid, $inheritanceType
}

function Rule-Equals {
  param(
    [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectoryAccessRule]$A,
    [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectoryAccessRule]$B
  )

  return (
    $A.IdentityReference -eq $B.IdentityReference -and
    $A.ActiveDirectoryRights -eq $B.ActiveDirectoryRights -and
    $A.AccessControlType -eq $B.AccessControlType -and
    $A.ObjectType -eq $B.ObjectType -and
    $A.InheritanceType -eq $B.InheritanceType -and
    $A.InheritedObjectType -eq $B.InheritedObjectType -and
    $A.IsInherited -eq $false -and
    $B.IsInherited -eq $false
  )
}

function Confirm-Plan {
  param(
    [Parameter(Mandatory = $true)][object[]]$PlanRows,
    [Parameter(Mandatory = $true)][switch]$SkipPrompt
  )

  Write-Info ""
  Write-Info "Planned ACE additions:"
  Write-Info "----------------------"

  $PlanRows |
    Sort-Object Rights, AttributeName |
    Format-Table -AutoSize OU, Principal, Rights, AttributeName, AttributeGuid, Inheritance |
    Out-String |
    ForEach-Object { Write-Host $_.TrimEnd() }

  if ($SkipPrompt) {
    Write-Info "Confirmation: skipped (-Force specified)."
    return
  }

  $resp = Read-Host "Proceed with these ACL changes? Type YES to continue"
  if ($resp -ne 'YES') {
    throw "Aborted by operator."
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

# Validate OU exists
try {
  $null = Get-ADOrganizationalUnit -Server $Domain -Identity $ouDn -ErrorAction Stop
} catch {
  throw "OU not found or not accessible: $ouDn. Error: $($_.Exception.Message)"
}

$principalObj = Resolve-Principal -Identity $Principal -Server $Domain -Order $resolveOrder

# Parse attributes (force array output even for a single attribute)
$attrList = @(
  $Attribute.Split(',') |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -ne '' } |
    Select-Object -Unique
)

if ($attrList.Count -eq 0) {
  Throw-ArgError "Attribute list is empty."
}

Write-Info "Domain:          $Domain"
Write-Info "Domain DN:       $domainDn"
Write-Info "OU DN:           $ouDn"
Write-Info "Principal input: $Principal"
Write-Info "Resolved type:   $($principalObj.Type)"
Write-Info "Resolved name:   $($principalObj.Name)"
Write-Info "Resolved DN:     $($principalObj.DN)"
Write-Info "Resolved SID:    $($principalObj.SID)"
Write-Info "Attributes:      $($attrList -join ', ')"
Write-Info "Mode:            $(if ($ReadWrite) { 'read-write' } else { 'read-only' })"

# Resolve attribute GUIDs
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

# Build the change plan and avoid duplicates
$acl = Get-ObjectAcl -DistinguishedName $ouDn

$readRight  = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
$writeRight = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty

$plan = @()
$rulesToAdd = @()

foreach ($r in $resolved) {
  $readRule = New-AttributeRule -Sid $principalObj.SID -AttributeGuid $r.Guid -Rights $readRight
  $wantRead = $true
  foreach ($existing in $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
    if ($existing -is [System.DirectoryServices.ActiveDirectoryAccessRule] -and (Rule-Equals -A $existing -B $readRule)) {
      $wantRead = $false
      break
    }
  }

  if ($wantRead) {
    $rulesToAdd += $readRule
    $plan += [PSCustomObject]@{
      OU            = $ouDn
      Principal     = "$($principalObj.Type):$($principalObj.Name)"
      Rights        = 'ReadProperty'
      AttributeName = $r.Name
      AttributeGuid = $r.Guid
      Inheritance   = 'All (this OU and descendants)'
    }
  }

  if ($ReadWrite) {
    $writeRule = New-AttributeRule -Sid $principalObj.SID -AttributeGuid $r.Guid -Rights $writeRight
    $wantWrite = $true
    foreach ($existing in $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
      if ($existing -is [System.DirectoryServices.ActiveDirectoryAccessRule] -and (Rule-Equals -A $existing -B $writeRule)) {
        $wantWrite = $false
        break
      }
    }

    if ($wantWrite) {
      $rulesToAdd += $writeRule
      $plan += [PSCustomObject]@{
        OU            = $ouDn
        Principal     = "$($principalObj.Type):$($principalObj.Name)"
        Rights        = 'WriteProperty'
        AttributeName = $r.Name
        AttributeGuid = $r.Guid
        Inheritance   = 'All (this OU and descendants)'
      }
    }
  }
}

if ($plan.Count -eq 0) {
  Write-Info ""
  Write-Info "No changes required. Matching explicit ACEs already exist."
  return
}

# Interactive confirmation unless -Force is specified
Confirm-Plan -PlanRows $plan -SkipPrompt:$Force

# Apply changes
Write-Info ""
Write-Info "Applying ACL changes to OU..."

foreach ($rule in $rulesToAdd) {
  $acl.AddAccessRule($rule) | Out-Null
}

Set-ObjectAcl -DistinguishedName $ouDn -Acl $acl
Write-Info "Done."