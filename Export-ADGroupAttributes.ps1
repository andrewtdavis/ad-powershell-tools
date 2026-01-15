<#
.SYNOPSIS
    Export all Active Directory attributes for a specified group in a specified domain.

.DESCRIPTION
    Retrieves all (or selected) Active Directory attributes for a given group.
    Attempts the ActiveDirectory module first (Get-ADGroup -Properties *); if not
    available, falls back to ADSI/DirectorySearcher.

    - Binary attributes are displayed as "BINARY (N bytes)".
    - Specific attributes can be selected via -Fields.
    - Output can be exported to CSV or JSON.

.PARAMETER Group
    sAMAccountName, CN, or DN of the group.

.PARAMETER Domain
    Domain FQDN or DC hostname, such as example.com or dc01.example.com.

.PARAMETER Fields
    Optional list of attribute names to output/export.

.PARAMETER OutCsv
    Optional CSV path.

.PARAMETER OutJson
    Optional JSON path.

.EXAMPLE
    .\Export-ADGroupAttributes.ps1 -Group "Domain Admins" -Domain example.com

.EXAMPLE
    .\Export-ADGroupAttributes.ps1 -Group mygroup -Domain example.com -Fields mail,managedBy -OutCsv mygroup.csv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)][Alias("h","help")][switch]$ShowHelp,
    [Parameter(Mandatory=$true,Position=0)][Alias("User")][string]$Group,
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

# Try ActiveDirectory module
try {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction Stop
        $usedADModule = $true
    }
} catch { }

if ($usedADModule) {
    try {
        $adParams = @{
            Identity    = $Group
            Properties  = '*'
            ErrorAction = 'Stop'
        }
        if ($Domain)      { $adParams['Server']     = $Domain }
        if ($Credential)  { $adParams['Credential'] = $Credential }

        $adGroup = Get-ADGroup @adParams
        if (-not $adGroup) { throw "Group not found via Get-ADGroup" }

        foreach ($name in $adGroup.PropertyNames) {
            $val = $adGroup.$name
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

        if ($adGroup.DistinguishedName -and -not $results.ContainsKey('DistinguishedName')) {
            $results['DistinguishedName'] = $adGroup.DistinguishedName
        }
    } catch {
        Write-Warning "Get-ADGroup failed, falling back to ADSI: $_"
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
    $escaped = [System.DirectoryServices.Protocols.LdapEncoder]::FilterEncode($Group)
    $searcher.Filter = "(&(objectClass=group)(|(sAMAccountName=$escaped)(cn=$escaped)(distinguishedName=$escaped)))"
    $searcher.PageSize = 1000
    $searcher.SizeLimit = 1
    $res = $searcher.FindOne()
    if (-not $res) { throw "Group not found in ADSI search." }
    $deGroup = $res.GetDirectoryEntry()

    foreach ($propName in $deGroup.Properties.PropertyNames) {
        $vals = $deGroup.Properties[$propName]
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

    $results['ADSI_Path'] = $deGroup.Path
    $results['SchemaClassName'] = $deGroup.SchemaClassName
}

# Handle attribute filtering
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

Write-Host "=== AD attribute export for group '$Group' in '$Domain' ===`n"
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