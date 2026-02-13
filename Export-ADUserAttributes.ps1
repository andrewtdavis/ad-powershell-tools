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
    - If -Domain is a DC hostname, RootDSE is queried to discover defaultNamingContext.

    Lookup behavior:
    - Default mode uses -User and matches sAMAccountName, userPrincipalName, or distinguishedName.
    - If -LookupField and -LookupValue are specified, the script searches by that attribute instead.

    Output behavior:
    - Binary attributes are shown as "BINARY (N bytes)".
    - Use -Fields to limit output to a specific set of attributes.
    - Use -OutCsv and/or -OutJson to export results.

  Parameters:
    -User
      sAMAccountName, UPN, or DN of the user (default lookup mode).

    -Domain
      Optional. Domain FQDN, DC hostname, or BaseDN.
      Examples: example.com, dc01.example.com, DC=example,DC=com
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

    .\Export-ADUserAttributes.ps1 -LookupField uid -LookupValue mchen -Fields uid,uidNumber,gladstone_ucsfid
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

function Convert-DomainToBaseDN {
    param([Parameter(Mandatory = $true)][string]$DomainName)
    ($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','
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

function Resolve-LdapTargets {
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

    $rootPath = $null
    if ($server) {
        $rootPath = "LDAP://{0}/{1}" -f $server, $baseDn
    } else {
        $rootPath = "LDAP://{0}" -f $baseDn
    }

    [pscustomobject]@{
        Server         = $server
        BaseDN         = $baseDn
        SearchRootPath = $rootPath
    }
}

function Escape-LdapFilterValue {
    <#
      Escapes LDAP filter assertion values per RFC 4515.
      Escapes: \ * ( ) and NUL as \5c \2a \28 \29 \00

      Returns:
      - Escaped string safe for use inside (...) filter components.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    if ($null -eq $Value) { return "" }

    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int][char]$ch
        switch ($code) {
            0      { [void]$sb.Append('\00') }
            40     { [void]$sb.Append('\28') } # (
            41     { [void]$sb.Append('\29') } # )
            42     { [void]$sb.Append('\2a') } # *
            92     { [void]$sb.Append('\5c') } # \
            default { [void]$sb.Append($ch) }
        }
    }
    $sb.ToString()
}

function Normalize-FieldsCaseInsensitive {
    param([string[]]$Fields)
    $ht = @{}
    foreach ($f in ($Fields | Where-Object { $_ -and $_.Trim() })) {
        $ht[$f.Trim().ToLowerInvariant()] = $f.Trim()
    }
    $ht
}

# Parameter validation
$User = if ($User) { $User.Trim() } else { $null }
$LookupField = if ($LookupField) { $LookupField.Trim() } else { $null }
$LookupValue = if ($LookupValue) { $LookupValue.Trim() } else { $null }

if ((-not $User) -and (-not $LookupField)) {
    throw "Specify either -User, or -LookupField and -LookupValue."
}
if ($LookupField -and (-not $LookupValue)) {
    throw "-LookupValue is required when -LookupField is specified."
}
if ($LookupValue -and (-not $LookupField)) {
    throw "-LookupField is required when -LookupValue is specified."
}
if ($LookupField -and $LookupValue -eq "") {
    throw "-LookupValue must not be empty."
}

# Domain label + target selection
$domainLabel = $Domain
$domainForTargets = $Domain

if (-not $Domain -or -not $Domain.Trim()) {
    $d = Get-DefaultBoundDomain
    if (-not $d) {
        $domainLabel = "<auto>"
        $domainForTargets = $null
    } else {
        $domainLabel = $d
        $domainForTargets = $d
    }
} else {
    $domainLabel = $Domain.Trim()
    $domainForTargets = $Domain.Trim()
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
        if ($domainForTargets) {
            $serverParam = $domainForTargets
        }

        $adUser = $null

        if ($LookupField) {
            $escapedVal = Escape-LdapFilterValue -Value $LookupValue
            $escapedField = $LookupField
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
    $targets = Resolve-LdapTargets -DomainOrServer $domainForTargets -Credential $Credential

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
        $escapedField = $LookupField
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

# If user asked for just certain attributes, filter now (case-insensitive)
if ($Fields -and $Fields.Count -gt 0) {
    $fieldMap = Normalize-FieldsCaseInsensitive -Fields $Fields
    $requested = @{}

    foreach ($k in $fieldMap.Keys) {
        $originalField = $fieldMap[$k]

        $matchKey = $null
        foreach ($rk in $results.Keys) {
            if ($rk.ToLowerInvariant() -eq $k) { $matchKey = $rk; break }
        }

        if ($matchKey) {
            $requested[$originalField] = $results[$matchKey]
        } else {
            $requested[$originalField] = '<not found>'
        }
    }

    $results = $requested
}

if ($LookupField) {
    Write-Host ("=== AD attribute dump for lookup: {0} = '{1}' (Domain: {2}) ===`n" -f $LookupField, $LookupValue, $domainLabel)
} else {
    Write-Host ("=== AD attribute dump for '{0}' (Domain: {1}) ===`n" -f $User, $domainLabel)
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