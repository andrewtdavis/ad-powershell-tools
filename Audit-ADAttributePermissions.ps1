<#
.SYNOPSIS
Audits Active Directory OU ACLs for attribute-related permissions that go beyond a baseline set of default principals.

.DESCRIPTION
Enumerates all Organizational Units in a target domain and inspects each OU's security descriptor (DACL)
to find Access Control Entries (ACEs) that can result in effective read/write access for a specified set
of attributes.

This audit focuses on attribute-relevant rights:
  - ReadProperty / WriteProperty (attribute-specific and all-properties)
  - GenericRead / GenericWrite / GenericAll
  - Optionally: WriteDacl / WriteOwner as "CanGrant"

This audit is designed to answer:
  - Which OUs have delegations for these attributes?
  - Which identities (users/groups, well-known SIDs, unresolved SIDs) have those rights?
  - Which entries are likely "non-default" because they are granted to identities outside a baseline set
    of common built-in/admin principals?

Baseline determination:
  - This script uses a heuristic baseline list of principals commonly present in default Microsoft ACLs:
      - Everyone, Authenticated Users, SELF, LOCAL SYSTEM
      - BUILTIN\Administrators and other BUILTIN operator groups
      - Domain Admins, Enterprise Admins, Schema Admins, Group Policy Creator Owners (known RIDs)
      - Administrators (domain local - RID 544) when applicable
  - Any identity not matching this baseline list is flagged as NonDefaultIdentity = $true.
  - Additionally, any explicit (non-inherited) ACE granting relevant rights is flagged ExplicitDelegation = $true.

Important limitations:
  - This does not attempt to fully reproduce Microsoft default ACL templates per OU or per OS build.
  - Deny ACE handling is optional; denies are reported but not used to compute full Windows effective access.
  - Central Access Policies, claims, and permissions derived from other directory objects are not evaluated.
  - This audit is scoped to OU objects only.

.PARAMETER Domain
DNS name of the AD domain to audit. Example: corp.example.com

.PARAMETER Attribute
Comma-separated list of attribute LDAP display names to audit.
Example: "uid,uidNumber,gidNumber,unixHomeDirectory,loginShell"

.PARAMETER IncludeInherited
Include inherited ACEs in the audit results. Default: enabled.

.PARAMETER IncludeDeny
Include deny ACEs in the audit results. Default: disabled.

.PARAMETER IncludeGrantCapable
Include WriteDacl/WriteOwner ACEs (flagged as CanGrant) in results. Default: enabled.

.PARAMETER OnlyNonDefault
Only output rows where NonDefaultIdentity is $true OR ExplicitDelegation is $true.
Default: enabled.

.PARAMETER ExportTsv
Optional path to write results as a TSV file (UTF8). If omitted, results are printed as a table.

.PARAMETER Table
Print results to console as a formatted table (default behavior if ExportTsv is not provided).

.PARAMETER MaxRows
Optional cap on the number of output rows. Useful for quick checks.

.EXAMPLE
# Print a console table of non-default delegations for common RFC2307 attributes
.\Audit-ADAttributePermissions.ps1 `
  -Domain "corp.example.com" `
  -Attribute "uid,uidNumber,gidNumber,unixHomeDirectory,loginShell" `
  -ReadWrite `
  -Table

.EXAMPLE
# Export a TSV for offline review
.\Audit-ADAttributePermissions.ps1 `
  -Domain "corp.example.com" `
  -Attribute "uid,uidNumber,gidNumber" `
  -ReadWrite `
  -ExportTsv ".\ad_attribute_acl_audit.tsv"

.EXAMPLE
# Include inherited + default principals (full picture), and include deny ACEs
.\Audit-ADAttributePermissions.ps1 `
  -Domain "corp.example.com" `
  -Attribute "uidNumber" `
  -ReadWrite `
  -IncludeDeny `
  -OnlyNonDefault:$false `
  -ExportTsv ".\full_acl_audit.tsv"
#>

[CmdletBinding(DefaultParameterSetName = 'ReadOnly')]
param(
  [Parameter(Mandatory = $true)]
  [string]$Domain,

  [Parameter(Mandatory = $true)]
  [string]$Attribute,

  [Parameter(Mandatory = $true, ParameterSetName = 'ReadOnly')]
  [switch]$ReadOnly,

  [Parameter(Mandatory = $true, ParameterSetName = 'ReadWrite')]
  [switch]$ReadWrite,

  [switch]$IncludeInherited = $true,

  [switch]$IncludeDeny,

  [switch]$IncludeGrantCapable = $true,

  [switch]$OnlyNonDefault = $true,

  [string]$ExportTsv,

  [switch]$Table,

  [int]$MaxRows = 0
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
  Get-Acl -Path $path -ErrorAction Stop
}

function Get-KnownSidLabelMap {
  param([Parameter(Mandatory = $true)][string]$Server)

  # Well-known SIDs (not domain-specific)
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

  # Domain and forest-root RID-based groups (domain-specific)
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
    $map["$domainSid-544"] = 'Administrators (RID 544) [domain local]'
  }

  if ($forestRootSid) {
    $map["$forestRootSid-518"] = 'Schema Admins (RID 518) [forest root]'
    $map["$forestRootSid-519"] = 'Enterprise Admins (RID 519) [forest root]'
  }

  return $map
}

function Get-DomainSidAnnotation {
  param([Parameter(Mandatory = $true)][string]$SidString)

  # Annotate unresolved S-1-5-21-...-RID SIDs with their base domain SID.
  if ($SidString -notmatch '^S-1-5-21-(\d+)-(\d+)-(\d+)-(\d+)$') { return $null }

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

function Test-IsBaselineIdentity {
  param(
    [Parameter(Mandatory = $true)][string]$SidString,
    [Parameter(Mandatory = $true)][string]$IdentityName
  )

  # Baseline heuristic:
  # - Any SID in S-1-5-32-* (BUILTIN\*) is treated as baseline
  # - Well-known global SIDs: Everyone/Auth Users/SELF/SYSTEM
  # - Known RID-based admin groups labeled via map (Domain Admins/Enterprise Admins/Schema Admins/GP Creators)
  # - Any identity name that starts with "NT AUTHORITY\" treated as baseline (SYSTEM/SELF etc)
  if ($SidString -match '^S-1-5-32-') { return $true }
  if ($SidString -in @('S-1-1-0','S-1-5-11','S-1-5-10','S-1-5-18')) { return $true }
  if ($IdentityName -match '^(?i)NT AUTHORITY\\') { return $true }
  if ($IdentityName -match 'RID 51(2|8|9)|Group Policy Creator Owners') { return $true }
  return $false
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

  # Relevant to attribute:
  # - ObjectType = attribute GUID (property-specific)
  # - ObjectType = empty GUID (applies to all properties for ReadProperty/WriteProperty)
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

function Parse-AttributeList {
  param([Parameter(Mandatory = $true)][string]$AttributeString)

  @(
    $AttributeString.Split(',') |
      ForEach-Object { $_.Trim() } |
      Where-Object { $_ -ne '' } |
      Select-Object -Unique
  )
}

# Main
Ensure-ActiveDirectoryModule

$attrList = Parse-AttributeList -AttributeString $Attribute
if ($attrList.Count -eq 0) { Throw-ArgError "Attribute list is empty." }

$domainDn = Get-DomainDnFromDns -DnsName $Domain

# Validate domain is reachable
try {
  $null = Get-ADDomain -Server $Domain -ErrorAction Stop
} catch {
  throw "Domain lookup failed for '$Domain'. Error: $($_.Exception.Message)"
}

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

$knownSidLabels = Get-KnownSidLabelMap -Server $Domain

$wantRead = $true
$wantWrite = $false
if ($ReadWrite) { $wantWrite = $true }

$searchBase = $domainDn

# Enumerate all OUs
$ous = Get-ADOrganizationalUnit -Server $Domain -Filter * -SearchBase $searchBase -Properties DistinguishedName, Name

$results = New-Object System.Collections.Generic.List[object]

foreach ($ouObj in $ous) {
  $ouDn = $ouObj.DistinguishedName

  $acl = $null
  try {
    $acl = Get-ObjectAcl -DistinguishedName $ouDn
  } catch {
    $results.Add([PSCustomObject]@{
      OU              = $ouDn
      OUName          = $ouObj.Name
      AttributeName   = ''
      AttributeGuid   = ''
      AppliesTo       = ''
      GrantTypes      = ''
      AccessType      = ''
      Rights          = ''
      IdentityName    = ''
      IdentitySid     = ''
      IsInherited     = $null
      ExplicitDelegation = $null
      BaselineIdentity   = $null
      NonDefaultIdentity = $null
      Note            = "Failed to read ACL: $($_.Exception.Message)"
    }) | Out-Null
    continue
  }

  foreach ($attr in $resolved) {
    $aces = Get-RelevantAcesForAttribute -Acl $acl -AttrGuid $attr.Guid -IncludeInherited:$IncludeInherited -IncludeDeny:$IncludeDeny

    foreach ($ace in $aces) {
      $sid = [System.Security.Principal.SecurityIdentifier]$ace.IdentityReference
      $sidStr = $sid.Value
      $friendly = Resolve-SidFriendly -Sid $sid -KnownSidLabels $knownSidLabels

      $class = Classify-AceForAccess -Ace $ace -AttrGuid $attr.Guid -WantRead:$wantRead -WantWrite:$wantWrite -IncludeGrantCapable:$IncludeGrantCapable

      $grantTypes = @()
      if ($class.ProvidesRead) { $grantTypes += 'Read' }
      if ($class.ProvidesWrite) { $grantTypes += 'Write' }
      if ($class.CanGrant) { $grantTypes += 'CanGrant' }
      if ($grantTypes.Count -eq 0) { continue }

      $appliesTo = if ($ace.ObjectType -eq [Guid]::Empty) { 'AllProperties' } else { 'AttributeOnly' }

      $explicit = -not [bool]$ace.IsInherited
      $baseline = Test-IsBaselineIdentity -SidString $sidStr -IdentityName $friendly
      $nonDefault = -not $baseline

      if ($OnlyNonDefault) {
        if (-not ($nonDefault -or $explicit)) { continue }
      }

      $results.Add([PSCustomObject]@{
        OU               = $ouDn
        OUName           = $ouObj.Name
        AttributeName    = $attr.Name
        AttributeGuid    = $attr.Guid
        AppliesTo        = $appliesTo
        GrantTypes       = ($grantTypes -join ',')
        AccessType       = $ace.AccessControlType.ToString()
        Rights           = $ace.ActiveDirectoryRights.ToString()
        IdentityName     = $friendly
        IdentitySid      = $sidStr
        IsInherited      = [bool]$ace.IsInherited
        ExplicitDelegation = $explicit
        BaselineIdentity   = $baseline
        NonDefaultIdentity = $nonDefault
        Note             = ''
      }) | Out-Null

      if ($MaxRows -gt 0 -and $results.Count -ge $MaxRows) { break }
    }

    if ($MaxRows -gt 0 -and $results.Count -ge $MaxRows) { break }
  }

  if ($MaxRows -gt 0 -and $results.Count -ge $MaxRows) { break }
}

# Output
if ($ExportTsv -and $ExportTsv.Trim() -ne '') {
  $dir = Split-Path -Parent $ExportTsv
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    Throw-ArgError "Export directory does not exist: $dir"
  }

  $results |
    Select-Object OU, OUName, AttributeName, GrantTypes, AppliesTo, AccessType, Rights, IdentityName, IdentitySid, IsInherited, ExplicitDelegation, BaselineIdentity, NonDefaultIdentity, Note |
    Export-Csv -Delimiter "`t" -NoTypeInformation -Encoding UTF8 -Path $ExportTsv

  Write-Host "Wrote TSV: $ExportTsv"
  return
}

# Default to table output
$results |
  Sort-Object OUName, AttributeName, GrantTypes, IdentityName, IsInherited |
  Select-Object OUName, AttributeName, GrantTypes, IdentityName, IsInherited, ExplicitDelegation, NonDefaultIdentity |
  Format-Table -AutoSize |
  Out-String |
  ForEach-Object { Write-Host $_.TrimEnd() }