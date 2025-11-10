<#
.SYNOPSIS
    Retrieve RFC2307 (Unix) attributes for an Active Directory user.

.DESCRIPTION
    Looks up an AD user account by email address and displays
    the Unix-related attributes used for NFS / LDAP integration:
    uid, uidNumber, gidNumber, gecos, and unixHomeDirectory.

    Accepts input either via:
      - the -Email flag,
      - a single positional argument,
      - or interactive prompt if none provided.

    The script validates the input to ensure it looks like an email address
    before performing the query.

.EXAMPLES
    PS C:\> .\Get-UnixAttributes.ps1 -Email alice@example.org
    PS C:\> .\Get-UnixAttributes.ps1 alice@example.org
    PS C:\> .\Get-UnixAttributes.ps1
    (then enter the email address interactively)

.NOTES
    Requires the ActiveDirectory module (RSAT: Active Directory tools).

.AUTHOR
    Andrew Davis <andrew.davis@gladstone.ucsf.edu>
#>

 param(
    [string]$Email
)

# If they ran: .\Get-UnixAttributes.ps1 someone@org.org
# PowerShell will put that in $args, so let's honor that too.
if (-not $Email -and $args.Count -gt 0) {
    $Email = $args[0]
}

if (($args.Count -gt 0) -and ($args[0] -in @("-h","--help","/h","/?"))) {
    Write-Host "Gladstone Get Unix Extensions Script`n"
    Write-Host 'USAGE: Get-UnixAttributes.ps1 -Email <email>'
    Write-Host '   or: Get-UnixAttributes.ps1 <email>'
    exit 0
}

# Prompt if still empty
if (-not $Email) {
    $Email = Read-Host "No email address specified, please enter one"
}

# quick-and-dirty email pattern
$emailPattern = '^[^@\s]+@[^@\s]+\.[^@\s]+$'
if ($Email -notmatch $emailPattern) {
    Write-Host "The value '$Email' does not look like an email address. Exiting."
    exit 1
}

Import-Module ActiveDirectory

Write-Host "Getting AD user by email: $Email"

# Your original script used EmailAddress; keep that for consistency.
# If your environment actually uses 'mail', swap the filter to { mail -eq $Email }
$user = Get-ADUser -Filter { EmailAddress -eq $Email } -Properties uid,uidNumber,gidNumber,unixHomeDirectory,gecos,UserPrincipalName

if ($null -eq $user) {
    Write-Host "User lookup failed. Please check email address."
    exit 1
}

Write-Host "`nUser attributes:"
$user | Select-Object `
    Name,
    UserPrincipalName,
    uid,
    uidNumber,
    gidNumber,
    unixHomeDirectory,
    gecos
