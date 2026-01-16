# Active Directory PowerShell Tools

A collection of PowerShell scripts for querying and exporting Active Directory (AD) data, plus optional Delinea (Centrify) zone/profile lookups for RFC2307 / Unix identity attributes.

The repository is designed to be environment-agnostic. Examples use `example.com` and do not assume any specific organization.

## Prerequisites

### Active Directory (RSAT / ActiveDirectory module)

Most scripts require the **ActiveDirectory** PowerShell module (RSAT).

Install methods on Windows 11/10:

**Option 1: Settings UI**

1. Settings -> Apps -> Optional features
2. Select View features (or Add an optional feature)
3. Search for RSAT and install **RSAT: Active Directory Domain Services and Lightweight Directory Services Tools**

**Option 2: PowerShell (recommended for automation)**

List RSAT features and current state:

```powershell
Get-WindowsCapability -Online -Name RSAT* | Select-Object -Property DisplayName, Name, State
```

Install the AD DS / AD LDS tools (includes the ActiveDirectory module and ADUC MMC snap-in):

```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

Verify:

```powershell
Get-Module -ListAvailable ActiveDirectory
```

### Delinea / Centrify (optional)

Scripts that reference Delinea zones require the Delinea / Centrify PowerShell module, commonly published as `Centrify.DirectControl.PowerShell`.

## Getting help

All scripts include comment-based help. Use PowerShell help to view usage:

```powershell
Get-Help .\Get-UnixAttributes.ps1 -Full
Get-Help .\Export-AD-To-TSV.ps1 -Examples
```

## Scripts

### Export and reporting

- `Export-AD-To-TSV.ps1`
  - Searches for groups matching `-GroupPattern` under `-SearchDomain` and `-SearchBase`, expands membership recursively (cycle-safe), and writes one TSV per group.
  - Outputs are tab-separated to preserve commas in canonical names/paths.

- `Export-Groups-To-TSV.ps1`
  - Similar goal to `Export-AD-To-TSV.ps1`, with a DN-derived domain lookup strategy when resolving user objects.

- `Export-UPNs.ps1`
  - Resolves UPNs for a list of sAMAccountNames and can optionally format output as a simple HTML table (for email clients).

- `Export-ADUserAttributes.ps1`
  - Exports all (or selected) attributes for a user. Uses `Get-ADUser -Properties *` when available and falls back to ADSI/DirectorySearcher if needed.
  - Optional CSV and JSON outputs.

- `Export-ADGroupAttributes.ps1`
  - Exports all (or selected) attributes for a group. Uses `Get-ADGroup -Properties *` when available and falls back to ADSI/DirectorySearcher if needed.
  - Optional CSV and JSON outputs.

- `Get-ADUserCountsByDomain.ps1`
  - Counts users per domain.

- `Get-ADGroupCountsByDomain.ps1`
  - Counts groups per domain.

- `Get-DomainControllers.ps1`
  - Enumerates domain controllers for one or more domains. Optional site-based sorting.

- `Get-ADTrustCreationInfo.ps1`
  - Reports trust creation details where available.

### Group membership and troubleshooting

- `Get-ActiveGroupMembers.ps1`
  - Enumerates active user accounts in a group and supports cross-domain resolution.
  - Default output: `SamAccountName` values only (sorted, unique).
  - Structured output: use `-Name`, `-Email`, and/or `-Attributes` to add columns.
  - Export formats: `-Csv` or `-Tsv` (mutually exclusive). TSV output includes quoting for fields that contain tabs/newlines/quotes.
  - Domain targeting: `-Domains` controls where group resolution occurs and provides a fallback list for member resolution.

- `Get-ADUserGroups.ps1`
  - Enumerates group memberships for one or more users, including cross-domain scenarios.
  - Optional detailed TSV output and optional summary.

- `Get-GroupMemberGroupMembership.ps1`
  - For one or more groups, enumerates user members and then finds the forest-wide set of groups that list each user as a member.
  - Optional TSV output and optional summary.

- `Get-ADGroupBySid.ps1`
  - Resolves one or more SIDs to AD group objects across the forest.

- `Find-ADGroupCircularMembership.ps1`
  - Detects circular group nesting and outputs the cycles.

### RFC2307 / Unix identity attributes

- `Get-UnixAttributes.ps1`
  - Outputs RFC2307 attributes for a user.
  - The lookup attribute is controlled by `-IdentityType` (default: `Mail`).

- `Set-UnixAttributes.ps1`
  - Creates or updates RFC2307 attributes for a user.
  - Supports `-WhatIf` / `-Confirm` via `SupportsShouldProcess`.
  - The lookup attribute defaults to `mail` and can be changed via `-EmailAttribute`.

### Delinea integration

- `Export-Delinea-To-TSV.ps1`
  - Enumerates Delinea zones (optionally limited by `-CdmRootZonePath`), reads zone group profiles, resolves backing AD groups and expands membership on demand, and attempts to read per-zone Unix profile details for each user.
  - Writes per-zone TSV outputs.
  - Optional cache loading/writing via CLIXML.

- `Export-ADAndDelinea.ps1`
  - Convenience wrapper that runs an AD export phase (optional) and then a Delinea export phase with shared configuration.

## Notes on output formats

- TSV outputs are written using a tab delimiter so that canonical names and other fields containing commas remain unambiguous.
- CSV and JSON outputs (where offered) are intended for programmatic use.
