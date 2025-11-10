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
