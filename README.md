# Powershell Tools for Active Directory

_A collection of useful powershell tools to help with managing Active Directory especially around RFC2307 attributes._

### Files included:
- `Export-AD-To-TSV.ps1` - Exports active, Active Directory group members from a specific domain and search base (e.g. Builtin) using a wildcard pattern, and writes a TSV for each group with each members' SamAccountName, UserPrincipleName and ActiveDirectoryDomainServicesFolder.
- `Export-ADUserAttributes.ps1` - Versatile attributes exporter, which can dump all AD fields for a specific user, and optionally filter the output based on needed fields and supports CSV and JSON output for scripting.
- `Export-Delinea-To-TSV.ps1` - Uses the Delinea Access Manager (formerly Centrify) Powershell module to look up zone-specific Unix attributes based on Active Directory group pattern matching.
- `Export-UPNs.ps1` Exports the UPN of SamAccountNames for a specified list (file or other script), and optionally count and/or format with HTML for email.
- `Get-ActiveGroupMembers.ps1` Cross-domain aware lookup to export the SamAccountNames of all active users in a specified group.
- `Get-UnixAttributes.ps1` - Get the main RFC2307 attributes from a Active Directory user.
- `Set-UnixAttributes.ps1` - Set (or update) the main RFC2307 attributes of an Active Directory user.