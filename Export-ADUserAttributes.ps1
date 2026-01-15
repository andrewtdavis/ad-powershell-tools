<#
.SYNOPSIS
    Export Active Directory attributes for a specified user in a specified domain.

.DESCRIPTION
    Retrieves all (or selected) Active Directory attributes for a given user.
    Tries the ActiveDirectory module first (Get-ADUser -Properties *), and if that
    fails or isn’t available, falls back to ADSI/DirectorySearcher.

    - Binary attributes are shown as "BINARY (N bytes)".
    - You can limit output to specific attributes with -Fields.
    - You can export to CSV or JSON.

.PARAMETER User
    sAMAccountName, UPN, or DN of the user.

.PARAMETER Domain
    Domain FQDN or DC hostname (e.g. example.com or dc01.example.com).

.PARAMETER Fields
    Optional list of attribute names to output/export.

.PARAMETER OutCsv
    Optional CSV path.

.PARAMETER OutJson
    Optional JSON path.

.EXAMPLE
    .\Export-ADUserAttributes.ps1 -User jsmith -Domain example.com

.EXAMPLE
    .\Export-ADUserAttributes.ps1 -User jsmith -Domain example.com -Fields mail,department -OutCsv jsmith.csv

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)][Alias("h","help")][switch]$ShowHelp,
    [Parameter(Mandatory=$true,Position=0)][string]$User,
    [Parameter(Mandatory=$true,Position=1)][string]$Domain,
    [System.Management.Automation.PSCredential]$Credential = $null,
    [string[]]$Fields = @(),
    [string]$OutCsv = $null,
    [string]$OutJson = $null
)

if ($ShowHelp) {
    Get-Help -Full $MyInvocation.MyCommand.Path
    return
}

function Convert-DomainToBaseDN {
    param([string]$domain)
    if ($domain -match '\.') {
        return ($domain.Split('.') | ForEach-Object { "DC=$_" }) -join ','
    } else {
        $parts = $domain -split '\.'
        if ($parts.Count -ge 2) {
            return ($parts[1..($parts.Count-1)] | ForEach-Object { "DC=$_" }) -join ','
        } else {
            throw "Unable to convert domain to baseDN: $domain"
        }
    }
}

function Show-Binary {
    param([byte[]]$b)
    return ("BINARY ({0} bytes)" -f $b.Length)
}

$results = @{}
$usedADModule = $false

# Try ActiveDirectory module first
try {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction Stop
        $usedADModule = $true
    }
} catch { }

if ($usedADModule) {
    try {
        $adParams = @{
            Identity    = $User
            Properties  = '*'
            ErrorAction = 'Stop'
        }
        if ($Domain)      { $adParams['Server']     = $Domain }
        if ($Credential)  { $adParams['Credential'] = $Credential }

        $adUser = Get-ADUser @adParams
        if (-not $adUser) { throw "User not found via Get-ADUser" }

        foreach ($name in $adUser.PropertyNames) {
            $val = $adUser.$name
            if ($null -eq $val) {
                $results[$name] = $null
                continue
            }

            if ($val -is [System.Collections.IEnumerable] -and -not ($val -is [string])) {
                $list = @()
                foreach ($item in $val) {
                    if ($item -is [byte[]]) { $list += (Show-Binary -b $item) }
                    else { $list += $item.ToString() }
                }
                $results[$name] = ($list -join '; ')
            }
            elseif ($val -is [byte[]]) {
                $results[$name] = Show-Binary -b $val
            }
            else {
                $results[$name] = $val.ToString()
            }
        }

        if ($adUser.DistinguishedName -and -not $results.ContainsKey('DistinguishedName')) {
            $results['DistinguishedName'] = $adUser.DistinguishedName
        }
    } catch {
        Write-Warning "Get-ADUser failed, falling back to ADSI: $_"
        $usedADModule = $false
    }
}

if (-not $usedADModule) {
    $baseDN = Convert-DomainToBaseDN -domain $Domain
    $ldapRoot = "LDAP://$baseDN"

    if ($Credential) {
        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        $rootDE = New-Object System.DirectoryServices.DirectoryEntry($ldapRoot, $username, $password)
    } else {
        $rootDE = New-Object System.DirectoryServices.DirectoryEntry($ldapRoot)
    }

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = $rootDE
    $escaped = [System.DirectoryServices.Protocols.LdapEncoder]::FilterEncode($User)
    $searcher.Filter = "(&(|(sAMAccountName=$escaped)(userPrincipalName=$escaped)(distinguishedName=$escaped)))"
    $searcher.PageSize = 1000
    $searcher.SizeLimit = 1
    $res = $searcher.FindOne()
    if (-not $res) { throw "User not found in ADSI search." }
    $deUser = $res.GetDirectoryEntry()

    foreach ($propName in $deUser.Properties.PropertyNames) {
        $vals = $deUser.Properties[$propName]
        if ($vals.Count -eq 0) {
            $results[$propName] = $null
        } elseif ($vals.Count -eq 1) {
            $single = $vals[0]
            if ($single -is [byte[]]) { $results[$propName] = Show-Binary -b $single }
            else { $results[$propName] = $single.ToString() }
        } else {
            $out = @()
            foreach ($v in $vals) {
                if ($v -is [byte[]]) { $out += (Show-Binary -b $v) }
                else { $out += $v.ToString() }
            }
            $results[$propName] = ($out -join '; ')
        }
    }

    $results['ADSI_Path'] = $deUser.Path
    $results['SchemaClassName'] = $deUser.SchemaClassName
}

# If user asked for just certain attributes, filter now
if ($Fields -and $Fields.Count -gt 0) {
    $requested = @{}
    foreach ($f in $Fields) {
        if ($results.ContainsKey($f)) {
            $requested[$f] = $results[$f]
        } else {
            $requested[$f] = '<not found>'
        }
    }
    $results = $requested
}

Write-Host "=== AD attribute dump for '$User' in '$Domain' ===`n"
foreach ($key in $results.Keys | Sort-Object) {
    $val = $results[$key]
    if ($null -eq $val -or $val -eq '') { $val = '<null>' }
    Write-Host ("{0,-30}: {1}" -f $key, $val)
}

if ($OutCsv) {
    $obj = New-Object PSObject
    foreach ($k in $results.Keys) {
        $obj | Add-Member -NotePropertyName $k -NotePropertyValue $results[$k]
    }
    $obj | Export-Csv -Path $OutCsv -NoTypeInformation -Force
    Write-Host "Wrote CSV: $OutCsv"
}

if ($OutJson) {
    $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutJson -Encoding utf8
    Write-Host "Wrote JSON: $OutJson"
}
