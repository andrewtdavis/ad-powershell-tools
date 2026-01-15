 <#
.SYNOPSIS
    Looks up AD users by sAMAccountName and outputs sAMAccountName + UPN, or (optionally) counts UPN suffixes.

.DESCRIPTION
    This script takes sAMAccountNames from:
      - a text file via -File, OR
      - the pipeline / STDIN (e.g. another script that outputs SamAccountName),
    and looks each one up in Active Directory.

    By default, it outputs a per-user table:
        sAMAccountName | UserPrincipalName

    You can:
      - add -Email to include the AD mail attribute
      - add -Attributes "attr1,attr2" to include additional AD attributes
      - add -Count to show counts by UPN suffix instead of per-user rows
      - add -Clipboard to copy the chosen view to the clipboard as HTML for Outlook

.EXAMPLE
    .\Dump-UPNs.ps1 -File .\users.txt

.EXAMPLE
    .\Get-ActiveGroupMembers.ps1 "Finance-Team" | .\Dump-UPNs.ps1 -Email

.EXAMPLE
    .\Get-ActiveGroupMembers.ps1 "Finance-Team" | .\Dump-UPNs.ps1 -Count -Clipboard

.EXAMPLE
    .\Get-ActiveGroupMembers.ps1 "Finance-Team" | .\Dump-UPNs.ps1 -Attributes "mail,displayName" -Clipboard

.NOTES
    Requires: ActiveDirectory module
    Works on: Windows PowerShell 5.1 and PowerShell 7+

 # >

[CmdletBinding()]
param(
    # allow piped input directly to the script
    [Parameter(ValueFromPipeline = $true)]
    $InputObject,

    # AD domain to query; if omitted we detect the current one
    [string] $Domain,

    # Optional file containing sAMAccountNames (one per line)
    [string] $File,

    # Copy HTML table to clipboard for Outlook paste
    [switch] $Clipboard,

    # If set, show counts by UPN suffix instead of per-user rows
    [switch] $Count,

    # Convenience: include the 'mail' attribute in the per-user output
    [switch] $Email,

    # Comma-separated list of extra AD attributes to include in per-user output
    [string] $Attributes
)

Import-Module ActiveDirectory

if (-not $Domain) {
    $Domain = (Get-ADDomain).DNSRoot
}

# collect all input names
$allRaw = New-Object System.Collections.Generic.List[string]

# 1) from -File
if ($File) {
    (Get-Content -LiteralPath $File) | ForEach-Object {
        if ($_ -and $_.ToString().Trim() -ne '') {
            [void]$allRaw.Add($_.ToString())
        }
    }
}

# helper: pull a name off an object no matter how it was spelled
function Get-NameFromObject {
    param($obj)

    if ($obj -is [string]) {
        return $obj.Trim()
    }

    $props = $obj.PSObject.Properties
    foreach ($candidate in 'sAMAccountName','SamAccountName','SamAccountNAme','Name') {
        if ($props.Match($candidate).Count -gt 0) {
            $val = $props[$candidate].Value
            if ($val) { return $val.ToString().Trim() }
        }
    }

    return $null
}

# 2) from the first piped object
if ($PSBoundParameters.ContainsKey('InputObject') -and $null -ne $InputObject) {
    $n = Get-NameFromObject $InputObject
    if ($n) { [void]$allRaw.Add($n) }
}

# 3) from the rest of the pipeline
foreach ($item in $input) {
    $n = Get-NameFromObject $item
    if ($n) { [void]$allRaw.Add($n) }
}

if ($allRaw.Count -eq 0) {
    Write-Error "No input provided. Use -File or pipe objects / strings that have sAMAccountName / SamAccountName."
    return
}

# normalize and dedupe
$accountNames =
    $allRaw |
    Where-Object { $_ -and $_.Trim() -ne '' } |
    ForEach-Object {
        $line = $_.Trim()
        if ($line -match ',') {
            ($line -split ',')[0].Trim()
        } else {
            $line
        }
    } |
    Sort-Object -Unique

if ($accountNames.Count -eq 0) {
    Write-Error "No usable sAMAccountNames found in input."
    return
}

# figure out what extra attributes we need for per-user view
$extraAttrs = @()
if ($Email) {
    $extraAttrs += 'mail'
}
if ($Attributes) {
    $extraAttrs += ($Attributes -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
# dedupe extras
$extraAttrs = $extraAttrs | Sort-Object -Unique

# base AD properties we ALWAYS need
$baseProps = @('UserPrincipalName')
if ($extraAttrs.Count -gt 0) {
    $allProps = $baseProps + $extraAttrs
} else {
    $allProps = $baseProps
}

# lookup users
$results = foreach ($name in $accountNames) {
    try {
        $user = Get-ADUser -Server $Domain -Identity $name -Properties $allProps
        $upn  = $user.UserPrincipalName

        if ([string]::IsNullOrWhiteSpace($upn)) {
            $suffix = '(no UPN)'
        } else {
            $suffix = ($upn.Split('@')[-1]).Trim().ToLowerInvariant()
        }

        # build dynamic object
        $row = [ordered]@{
            sAMAccountName    = $user.sAMAccountName
            UserPrincipalName = $upn
            Suffix            = $suffix
        }

        foreach ($attr in $extraAttrs) {
            # add the property if present
            $row[$attr] = $user.$attr
        }

        [PSCustomObject]$row
    }
    catch {
        # user not found
        [PSCustomObject]@{
            sAMAccountName    = $name
            UserPrincipalName = $null
            Suffix            = '(not found)'
        }
    }
}

if ($Count) {
    # aggregated view – ignore extra attributes
    $summary =
        $results |
        Group-Object Suffix |
        Sort-Object @{Expression='Count';Descending=$true}, @{Expression='Name';Descending=$false} |
        Select-Object @{n='Suffix';e={$_.Name}}, @{n='Count';e={$_.Count}}

    if ($Clipboard) {
        $style = @"
<style>
table {border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:11pt}
th, td {border:1px solid #d0d0d0; padding:6px 10px; text-align:left}
th {background:#f3f3f3}
</style>
"@
        $html = ($summary | ConvertTo-Html -Property Suffix,Count -Head $style -PreContent "<h3>UPN Suffix Counts</h3>") -join "`n"

        if ($PSVersionTable.PSVersion.Major -ge 7) {
            Set-Clipboard -AsHtml $html
            Write-Host "HTML table copied to clipboard. Paste into Outlook."
        } else {
            Add-Type -AssemblyName System.Windows.Forms
            $doc = "<html><body><!--StartFragment-->$html<!--EndFragment--></body></html>"
            $pre = "Version:1.0`r`n"
            $startHtml = $pre.Length
            $startFragment = $startHtml + $doc.IndexOf("<!--StartFragment-->")
            $endFragment   = $startHtml + $doc.IndexOf("<!--EndFragment-->") + "<!--EndFragment-->".Length
            $endHtml       = $startHtml + $doc.Length
            $hdr = "StartHTML:{0:D10}`r`nEndHTML:{1:D10}`r`nStartFragment:{2:D10}`r`nEndFragment:{3:D10}`r`n" -f $startHtml,$endHtml,$startFragment,$endFragment
            [System.Windows.Forms.Clipboard]::SetText(($pre + $hdr + $doc), [System.Windows.Forms.TextDataFormat]::Html)
            Write-Host "HTML table copied to clipboard. Paste into Outlook."
        }
    }
    else {
        $summary | Format-Table -AutoSize
    }
}
else {
    # per-user view
    # columns: base ones + any extras
    $cols = @('sAMAccountName','UserPrincipalName')
    if ($extraAttrs.Count -gt 0) {
        $cols += $extraAttrs
    }

    $detail =
        $results |
        Select-Object $cols |
        Sort-Object sAMAccountName

    if ($Clipboard) {
        $style = @"
<style>
table {border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:11pt}
th, td {border:1px solid #d0d0d0; padding:6px 10px; text-align:left}
th {background:#f3f3f3}
</style>
"@
        $html = ($detail | ConvertTo-Html -Property $cols -Head $style -PreContent "<h3>AD Users</h3>") -join "`n"

        if ($PSVersionTable.PSVersion.Major -ge 7) {
            Set-Clipboard -AsHtml $html
            Write-Host "HTML table copied to clipboard. Paste into Outlook."
        } else {
            Add-Type -AssemblyName System.Windows.Forms
            $doc = "<html><body><!--StartFragment-->$html<!--EndFragment--></body></html>"
            $pre = "Version:1.0`r`n"
            $startHtml = $pre.Length
            $startFragment = $startHtml + $doc.IndexOf("<!--StartFragment-->")
            $endFragment   = $startHtml + $doc.IndexOf("<!--EndFragment-->") + "<!--EndFragment-->".Length
            $endHtml       = $startHtml + $doc.Length
            $hdr = "StartHTML:{0:D10}`r`nEndHTML:{1:D10}`r`nStartFragment:{2:D10}`r`nEndFragment:{3:D10}`r`n" -f $startHtml,$endHtml,$startFragment,$endFragment
            [System.Windows.Forms.Clipboard]::SetText(($pre + $hdr + $doc), [System.Windows.Forms.TextDataFormat]::Html)
            Write-Host "HTML table copied to clipboard. Paste into Outlook."
        }
    }
    else {
        $detail | Format-Table -AutoSize
    }
}
