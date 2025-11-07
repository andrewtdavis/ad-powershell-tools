 <#
.SYNOPSIS
    Uses the file users.txt to look up SamAccountName and UPN to copy/paste into an email
.DESCRIPTION
    Build a list of users, one per line in the file users.txt (can use Get-ActiveGroupMembers.ps1) for this), and
    then run this script to create a table of SamAccountName and UPN for each of the users in the file

.EXAMPLE
    .\Dump-UPNs.ps1

.NOTES
    Author: Andrew Davis
    Updated: 2025-10-28

#>

 function Set-ClipboardHtml {
  param([Parameter(Mandatory)][string]$HtmlFragment)

  Add-Type -AssemblyName System.Windows.Forms

  # Minimal HTML doc with fragment markers required by CF_HTML
  $doc = @"
<html><body>
<!--StartFragment-->$HtmlFragment<!--EndFragment-->
</body></html>
"@

  # CF_HTML header needs character offsets; OK as ASCII here
  $pre = "Version:1.0`r`n"
  $startHtml = $pre.Length
  $startFragment = $startHtml + $doc.IndexOf("<!--StartFragment-->")
  $endFragment   = $startHtml + $doc.IndexOf("<!--EndFragment-->") + "<!--EndFragment-->".Length
  $endHtml       = $startHtml + $doc.Length

  $hdr = "StartHTML:{0:D10}`r`nEndHTML:{1:D10}`r`nStartFragment:{2:D10}`r`nEndFragment:{3:D10}`r`n" -f $startHtml,$endHtml,$startFragment,$endFragment
  $cf  = $pre + $hdr + $doc

  [System.Windows.Forms.Clipboard]::SetText($cf, [System.Windows.Forms.TextDataFormat]::Html)
}

$users = Get-Content .\users.txt
Import-Module ActiveDirectory

$results = foreach ($u in $users) {
  try {
    Get-ADUser -Identity $u -Properties UserPrincipalName |
      Select-Object @{n='SamAccountName';e={$_.SamAccountName}},
                    @{n='UserPrincipalName';e={$_.UserPrincipalName}}
  } catch {
    [PSCustomObject]@{ SamAccountName = $u; UserPrincipalName = 'Not found' }
  }
}

$style = @"
<style>
table {border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:11pt}
th, td {border:1px solid #d0d0d0; padding:6px 10px; text-align:left}
th {background:#f3f3f3}
</style>
"@

# Create just the TABLE fragment (Outlook doesn’t need full <html> here)
$tableFragment = ($results | ConvertTo-Html -Property SamAccountName,UserPrincipalName -Fragment) -join "`n"
Set-ClipboardHtml -HtmlFragment ($style + $tableFragment)

Write-Host "Copied HTML table to clipboard. In Outlook, press Ctrl+V in your draft."
