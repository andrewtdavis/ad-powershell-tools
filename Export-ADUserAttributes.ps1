<#
.INFO
  Synopsis:
    Export Active Directory attributes for a user - by identity or by arbitrary attribute lookup.

  Description:
    Retrieves all (or selected) Active Directory attributes for a user. The script attempts to use
    the ActiveDirectory module first (Get-ADUser -Properties *). If the module is unavailable or
    the query fails, it falls back to ADSI (System.DirectoryServices.DirectorySearcher).

    Domain selection behavior:
    - If -Domain is not specified, the script attempts to determine the computer's joined AD domain.
    - If the system is not domain-joined and -Domain is not specified, the script fails with an error.
    - If -Domain is a DC hostname, the script queries RootDSE to discover the defaultNamingContext.

    Lookup behavior:
    - By default, -User matches sAMAccountName, userPrincipalName, or distinguishedName.
    - If -LookupField and -LookupValue are specified, the script searches by that attribute instead.

    Output behavior:
    - Binary attributes are shown as "BINARY (N bytes)".
    - Use -Fields to limit output to a specific set of attributes.
    - Use -OutCsv and/or -OutJson to export results.

  Parameters:
    -User
      sAMAccountName, UPN, or DN of the user (default lookup mode).

    -Domain
      Optional. Domain FQDN or DC hostname (example.com or dc01.example.com).
      If omitted, the computer's joined domain is used.

    -LookupField
      Optional. Attribute name to search by (for example: uidNumber, employeeID, mail).

    -LookupValue
      Optional. Attribute value to search for. Required when -LookupField is specified.

    -Credential
      Optional. PSCredential for the query.

    -Fields
      Optional. List of attribute names to output/export.

    -OutCsv
      Optional. CSV path.

    -OutJson
      Optional. JSON path.

  Examples:
    .\Export-ADUserAttributes.ps1 -User jsmith

    .\Export-ADUserAttributes.ps1 -User jsmith -Domain example.com -Fields mail,department -OutCsv jsmith.csv

    .\Export-ADUserAttributes.ps1 -LookupField uidNumber -LookupValue 123456 -Fields sAMAccountName,mail

    .\Export-ADUserAttributes.ps1 -LookupField employeeID -LookupValue E12345 -Domain dc01.example.com -OutJson user.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][Alias("h","help")][switch]$ShowHelp,

    [Parameter(Mandatory = $false, Position = 0)]
    [string]$User,

    [Parameter(Mandatory = $false, Position = 1)]
    [string]$Domain,

    [Parameter(Mandatory = $false)]
    [string]$LookupField,

    [Parameter(Mandatory = $false)]
    [string]$LookupValue,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential = $null,

    [Parameter(Mandatory = $false)]
    [string[]]$Fields = @(),

    [Parameter(Mandatory = $false)]
    [string]$OutCsv = $null,

    [Parameter(Mandatory = $false)]
    [string]$OutJson = $null
)

if ($ShowHelp) {
    Get-Help -Full $MyInvocation.MyCommand.Path
    return
}

function Show-Binary {
    param([byte[]]$b)
    "BINARY ({0} bytes)" -f $b.Length
}

function Get-DefaultBoundDomain {
    <#
      Attempts to discover the computer's joined AD domain.

      Order:
      - USERDNSDOMAIN environment variable
      - Win32_ComputerSystem.Domain (domain joined)
      - System.DirectoryServices.ActiveDirectory.Domain::GetComputerDomain()

      Returns:
      - Domain DNS name (example.com) or $null
    #>
    $d = $null

    try {
        if ($env:USERDNSDOMAIN -and $env:USERDNSDOMAIN.Trim()) {
            $d = $env:USERDNSDOMAIN.Trim()
        }
    } catch { }

    if (-not $d) {
        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            if ($cs.PartOfDomain -and $cs.Domain -and $cs.Domain.Trim()) {
                $d = $cs.Domain.Trim()
            }
        } catch { }
    }

    if (-not $d) {
        try {
            $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name
        } catch { }
    }

    $d
}

function Get-RootDseDefaultNamingContext {
    param(
        [Parameter(Mandatory = $true)][string]$ServerOrDomain,
        [System.Management.Automation.PSCredential]$Credential = $null
    )
    $path = "LDAP://{0}/RootDSE" -f $ServerOrDomain

    try {
        if ($Credential) {
            $u = $Credential.UserName
            $p = $Credential.GetNetworkCredential().Password
            $root = New-Object System.DirectoryServices.DirectoryEntry($path, $u, $p)
        } else {
            $root = New-Object System.DirectoryServices.DirectoryEntry($path)
        }

        $nc = $root.Properties["defaultNamingContext"].Value
        if ($nc -and $nc.ToString().Trim()) {
            return $nc.ToString().Trim()
        }
    } catch { }

    return $null
}

function Convert-DomainToBaseDN {
    param([Parameter(Mandatory = $true)][string]$DomainName)
    # Converts example.com -> DC=example,DC=com
    ($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','
}

function Resolve-LdapTargets {
    <#
      Produces LDAP connection targets for ADSI search.

      Returns an object with:
      - Server (optional)
      - BaseDN (required)
      - SearchRootPath (LDAP://... base)
    #>
    param(
        [Parameter(Mandatory = $false)][string]$DomainOrServer,
        [System.Management.Automation.PSCredential]$Credential = $null
    )

    $server = $null
    $baseDn = $null

    if ($DomainOrServer -and $DomainOrServer.Trim()) {
        $DomainOrServer = $DomainOrServer.Trim()

        if ($DomainOrServer -match '(^|,)\s*DC=') {
            $baseDn = $DomainOrServer
        } else {
            $server = $DomainOrServer
            $baseDn = Get-RootDseDefaultNamingContext -ServerOrDomain $server -Credential $Credential
            if (-not $baseDn) {
                # Fall back to assuming DNS domain input.
                $baseDn = Convert-DomainToBaseDN -DomainName $DomainOrServer
                $server = $null
            }
        }
    } else {
        $d = Get-DefaultBoundDomain
        if (-not $d) {
            throw "No -Domain specified and the system does not appear to be domain-joined."
        }
        $baseDn = Convert-DomainToBaseDN -DomainName $d
        $server = $null
    }

    $rootPath = if ($server) { "LDAP://{0}/{1}" -f $server, $baseDn } else { "LDAP://{0}" -f $baseDn }

    [pscustomobject]@{
        Server         = $server
        BaseDN         = $baseDn
        SearchRootPath = $rootPath
    }
}

function Escape-LdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    try {
        return [System.DirectoryServices.Protocols.LdapEncoder]::FilterEncode($Value)
    } catch {
        # Minimal safe fallback.
        $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([char]0, '\00')
    }
}

# Parameter validation
if (-not $User -and -not $LookupField) {
    throw "Specify either -User, or -LookupField and -LookupValue."
}
if ($LookupField -and (-not $LookupValue)) {
    throw "-LookupValue is required when -LookupField is specified."
}
if ($LookupValue -and (-not $LookupField)) {
    throw "-LookupField is required when -LookupValue is specified."
}

# Domain defaulting for display and AD-module server targeting
if (-not $Domain -or -not $Domain.Trim()) {
    $Domain = Get-DefaultBoundDomain
    if (-not $Domain) {
        $Domain = "<auto>"
    }
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
        $serverParam = $null
        if ($Domain -and $Domain -ne "<auto>" -and $Domain.Trim()) {
            $serverParam = $Domain.Trim()
        }

        if ($LookupField) {
            $escapedVal = Escape-LdapFilterValue -Value $LookupValue
            $escapedField = $LookupField.Trim()

            $ldapFilter = "(&(objectCategory=person)(objectClass=user)($escapedField=$escapedVal))"

            $adParams = @{
                LDAPFilter  = $ldapFilter
                Properties  = '*'
                ErrorAction = 'Stop'
            }
            if ($serverParam) { $adParams['Server'] = $serverParam }
            if ($Credential)  { $adParams['Credential'] = $Credential }

            $adUser = Get-ADUser @adParams | Select-Object -First 1
        } else {
            $adParams = @{
                Identity    = $User
                Properties  = '*'
                ErrorAction = 'Stop'
            }
            if ($serverParam) { $adParams['Server'] = $serverParam }
            if ($Credential)  { $adParams['Credential'] = $Credential }

            $adUser = Get-ADUser @adParams
        }

        if (-not $adUser) {
            if ($LookupField) { throw "User not found via Get-ADUser LDAP filter." }
            throw "User not found via Get-ADUser."
        }

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
        Write-Warning ("Get-ADUser failed, falling back to ADSI: {0}" -f $_)
        $usedADModule = $false
    }
}

if (-not $usedADModule) {
    $targets = Resolve-LdapTargets -DomainOrServer ($Domain -eq "<auto>" ? $null : $Domain) -Credential $Credential

    if ($Credential) {
        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        $rootDE = New-Object System.DirectoryServices.DirectoryEntry($targets.SearchRootPath, $username, $password)
    } else {
        $rootDE = New-Object System.DirectoryServices.DirectoryEntry($targets.SearchRootPath)
    }

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = $rootDE

    if ($LookupField) {
        $escapedVal = Escape-LdapFilterValue -Value $LookupValue
        $escapedField = $LookupField.Trim()
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user)($escapedField=$escapedVal))"
    } else {
        $escaped = Escape-LdapFilterValue -Value $User
        $searcher.Filter = "(&(|(sAMAccountName=$escaped)(userPrincipalName=$escaped)(distinguishedName=$escaped)))"
    }

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
    $results['BaseDN'] = $targets.BaseDN
    if ($targets.Server) { $results['ADSI_Server'] = $targets.Server }
}

# Field filtering
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

# Display banner
if ($LookupField) {
    Write-Host ("=== AD attribute dump for lookup: {0} = '{1}' (Domain: {2}) ===`n" -f $LookupField, $LookupValue, $Domain)
} else {
    Write-Host ("=== AD attribute dump for '{0}' (Domain: {1}) ===`n" -f $User, $Domain)
}

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
    Write-Host ("Wrote CSV: {0}" -f $OutCsv)
}

if ($OutJson) {
    $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutJson -Encoding utf8
    Write-Host ("Wrote JSON: {0}" -f $OutJson)
}