 <#
.SYNOPSIS
    List group memberships for one or more users across all domains in the forest.

.DESCRIPTION
    For each specified user (sAMAccountName, UPN, or DN, possibly in multiple
    domains):

      - Resolves the user in the correct domain:
          * If a DN is provided, the domain is derived from the DN.
          * Otherwise, the user is looked up in the -Domain parameter's domain
            (or forest-wide if -Domain is omitted).

      - Searches every domain in the forest for groups whose 'member' attribute
        contains that user's DN. This captures cross-domain memberships.

    Outputs only status messages and (optionally) a summary table.
    Use -OutTsv and -SummaryTsv for machine-readable output.

.PARAMETER Users
    One or more user identities:
      - sAMAccountName
      - UserPrincipalName (UPN)
      - DistinguishedName (CN=...,OU=...,DC=...,DC=...)

.PARAMETER Domain
    Optional: A domain FQDN (e.g. domain.example.com) used as:
      - The default place to resolve non-DN user identities.
      - The server for initial forest discovery.

    If omitted, forest discovery uses the current logon context.

.PARAMETER OutTsv
    Optional path to write detailed results to a TSV file.

.PARAMETER Summary
    If set, outputs a per-domain summary of memberships.

.PARAMETER SummaryTsv
    Optional path to write summary output to a TSV file.

.EXAMPLE
    .\Get-ADUserGroups.ps1 `
        -Users "jdoe" `
        -Domain "domain.example.com" `
        -OutTsv ".\user-groups.tsv" `
        -Summary `
        -SummaryTsv ".\user-groups-summary.tsv"

.EXAMPLE
    .\Get-ADUserGroups.ps1 `
        -Users "jdoe@domain.example.com","CN=Some User,OU=People,DC=domain,DC=example,DC=com" `
        -Summary
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string[]]$Users,

    [Parameter(Mandatory = $false)]
    [string]$Domain,

    [Parameter(Mandatory = $false)]
    [string]$OutTsv,

    [Parameter(Mandatory = $false)]
    [switch]$Summary,

    [Parameter(Mandatory = $false)]
    [string]$SummaryTsv
)

#region helper functions

function Ensure-ADModule {
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        $mod = Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue
        if (-not $mod) {
            throw "ActiveDirectory module is not available. Install RSAT / AD tools on this host."
        }
        Import-Module ActiveDirectory -ErrorAction Stop
    }
}

function Export-Tsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [Object[]]$InputObject
    )

    # Ensure directory exists
    $directory = [System.IO.Path]::GetDirectoryName($Path)
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $stream = New-Object System.IO.StreamWriter($Path, $false, [System.Text.Encoding]::UTF8)
    try {
        $headerWritten = $false

        foreach ($obj in $InputObject) {
            if (-not $headerWritten) {
                $header = ($obj.PSObject.Properties |
                           Where-Object { $_.MemberType -eq 'NoteProperty' } |
                           Select-Object -ExpandProperty Name) -join "`t"
                $stream.WriteLine($header)
                $headerWritten = $true
            }

            $values = $obj.PSObject.Properties |
                      Where-Object { $_.MemberType -eq 'NoteProperty' } |
                      ForEach-Object {
                          # Replace tabs to avoid breaking TSV format
                          ($_.Value -replace "`t"," ")
                      }

            $stream.WriteLine(($values -join "`t"))
        }
    }
    finally {
        $stream.Close()
    }
}

function Get-DomainFromDN {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName
    )

    if (-not $DistinguishedName) { return $null }

    $dcParts = ($DistinguishedName -split ',') |
        Where-Object { $_ -like 'DC=*' } |
        ForEach-Object { $_.Substring(3) }

    if ($dcParts.Count -gt 0) {
        return ($dcParts -join '.')
    } else {
        return $null
    }
}

function Escape-LdapFilterValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        switch ($ch) {
            '(' { [void]$sb.Append('\28') }
            ')' { [void]$sb.Append('\29') }
            '*' { [void]$sb.Append('\2a') }
            '\' { [void]$sb.Append('\5c') }
            ([char]0) { [void]$sb.Append('\00') }
            default { [void]$sb.Append($ch) }
        }
    }
    $sb.ToString()
}

function Get-ForestDomainMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Server
    )

    if ($Server) {
        $forest = Get-ADForest -Server $Server -ErrorAction Stop
    }
    else {
        $forest = Get-ADForest -ErrorAction Stop
    }

    $domainMap = @{}     # fqdn (lower) -> DC hostname
    $domainList = @()    # list of DC hostnames (for brute-force loops)

    foreach ($dom in $forest.Domains) {
        $lower = $dom.ToLower()
        try {
            # Prefer a DC that actually responds; start with PDC
            $dc = Get-ADDomainController -DomainName $dom -Discover -Service PrimaryDC -ErrorAction Stop
        }
        catch {
            try {
                $dc = Get-ADDomainController -DomainName $dom -Discover -ErrorAction Stop
            }
            catch {
                Write-Warning "Could not discover a DC for domain '$dom': $($_.Exception.Message)"
                continue
            }
        }

        $domainMap[$lower] = $dc.HostName
        $domainList += $dc.HostName
    }

    return [PSCustomObject]@{
        ForestName   = $forest.Name
        DomainMap    = $domainMap     # fqdn (lower) -> DC
        DomainDCList = $domainList    # list of DC hostnames
    }
}

function Get-ServerForDomain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        [Parameter(Mandatory = $true)]
        [hashtable]$DomainMap
    )

    if (-not $DomainName) { return $null }

    $key = $DomainName.ToLower()
    if ($DomainMap.ContainsKey($key)) {
        return $DomainMap[$key]
    }

    # Fallback: try to use the domain name itself as server
    return $DomainName
}

function Resolve-User {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId,

        [Parameter(Mandatory = $false)]
        [string]$DefaultDomain,

        [Parameter(Mandatory = $true)]
        [hashtable]$DomainMap,

        [Parameter(Mandatory = $true)]
        [string[]]$DomainDCList
    )

    # If this looks like a DN, derive domain from it
    if ($UserId -match '^.+?,DC=.+') {
        $userDomain = Get-DomainFromDN -DistinguishedName $UserId
        $server = Get-ServerForDomain -DomainName $userDomain -DomainMap $DomainMap
        try {
            return Get-ADUser -Identity $UserId -Server $server -Properties displayName, userPrincipalName -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to resolve user DN '$UserId' in domain '$userDomain': $($_.Exception.Message)"
            return $null
        }
    }

    # Try DefaultDomain if provided
    if ($DefaultDomain) {
        $server = Get-ServerForDomain -DomainName $DefaultDomain -DomainMap $DomainMap
        try {
            # Try identity directly first (covers samAccountName and UPN when unique)
            $u = Get-ADUser -Identity $UserId -Server $server -Properties displayName, userPrincipalName -ErrorAction SilentlyContinue
            if ($u) { return $u }

            # Try matching on sAMAccountName or UPN explicitly
            $filter = "(samAccountName -eq '$UserId' -or UserPrincipalName -eq '$UserId')"
            $u = Get-ADUser -Server $server -Filter $filter -Properties displayName, userPrincipalName -ErrorAction SilentlyContinue
            if ($u) { return $u }
        }
        catch {
            Write-Warning "Failed to resolve user '$UserId' in default domain '$DefaultDomain': $($_.Exception.Message)"
        }
    }

    # Last resort: hunt in all domains
    foreach ($dc in $DomainDCList) {
        try {
            $u = Get-ADUser -Identity $UserId -Server $dc -Properties displayName, userPrincipalName -ErrorAction SilentlyContinue
            if ($u) { return $u }

            $filter = "(samAccountName -eq '$UserId' -or UserPrincipalName -eq '$UserId')"
            $u = Get-ADUser -Server $dc -Filter $filter -Properties displayName, userPrincipalName -ErrorAction SilentlyContinue
            if ($u) { return $u }
        }
        catch { }
    }

    Write-Warning "Unable to resolve user '$UserId' in any known domain."
    return $null
}

#endregion helper functions

try {
    Ensure-ADModule
}
catch {
    Write-Error $_
    return
}

# Build forest-wide domain map
try {
    $forestMap = Get-ForestDomainMap -Server $Domain
}
catch {
    Write-Error "Failed to discover forest/domain information: $($_.Exception.Message)"
    return
}

$domainMap    = $forestMap.DomainMap
$domainDCList = $forestMap.DomainDCList

if (-not $domainMap.Keys.Count) {
    Write-Error "No domains/DCs discovered in the forest. Cannot continue."
    return
}

$allResults = @()

foreach ($userId in $Users) {

    $user = Resolve-User -UserId $userId -DefaultDomain $Domain -DomainMap $domainMap -DomainDCList $domainDCList
    if (-not $user) { continue }

    $userDN        = $user.DistinguishedName
    $userDomain    = Get-DomainFromDN -DistinguishedName $userDN
    $escapedUserDN = Escape-LdapFilterValue -Value $userDN

    Write-Host "Processing user '$($user.SamAccountName)' in domain '$userDomain'..."

    $membershipGroups = @()

    # Search every domain for groups containing this user's DN in 'member'
    foreach ($dc in $domainDCList) {
        try {
            $groupsForUser = Get-ADGroup -Server $dc -LDAPFilter "(member=$escapedUserDN)" -ErrorAction SilentlyContinue
            if ($groupsForUser) {
                $membershipGroups += $groupsForUser
            }
        }
        catch {
            Write-Verbose "Membership search failed for user '$($user.SamAccountName)' on DC '$dc': $($_.Exception.Message)"
        }
    }

    # Deduplicate by DN
    $uniqueMembershipGroups = $membershipGroups |
        Group-Object DistinguishedName |
        ForEach-Object { $_.Group[0] }

    foreach ($mg in $uniqueMembershipGroups) {
        $mgDomain = Get-DomainFromDN -DistinguishedName $mg.DistinguishedName

        $row = [PSCustomObject]@{
            MemberSamAccountName  = $user.SamAccountName
            MemberDisplayName     = $user.DisplayName
            MemberUPN             = $user.UserPrincipalName
            MemberDN              = $user.DistinguishedName

            MembershipGroupName   = $mg.Name
            MembershipGroupSam    = $mg.SamAccountName
            MembershipGroupDN     = $mg.DistinguishedName
            MembershipGroupDomain = $mgDomain
        }

        $allResults += $row
    }
}

if (-not $allResults -or $allResults.Count -eq 0) {
    Write-Warning "No membership data collected."
    return
}

Write-Host "Collected $($allResults.Count) membership rows."

# Optional detailed TSV
if ($OutTsv) {
    try {
        if (-not [System.IO.Path]::IsPathRooted($OutTsv)) {
            $OutTsv = (Join-Path -Path (Get-Location) -ChildPath $OutTsv)
        }

        Export-Tsv -Path $OutTsv -InputObject $allResults
        Write-Host "Detailed membership TSV written to: $OutTsv"
    }
    catch {
        Write-Warning "Failed to write TSV '$OutTsv': $($_.Exception.Message)"
    }
}

# Optional summary
if ($Summary.IsPresent) {
    $summaryData = $allResults |
        Group-Object MembershipGroupDomain |
        Select-Object @{
                Name       = 'Domain'
                Expression = { if ($_.Name) { $_.Name } else { '(no DC in DN)' } }
            },
            @{
                Name       = 'UniqueGroups'
                Expression = {
                    ($_.Group |
                        Select-Object -ExpandProperty MembershipGroupDN -Unique).Count
                }
            },
            @{
                Name       = 'TotalMembershipRows'
                Expression = { $_.Count }
            }

    Write-Host ""
    Write-Host "Summary of group memberships by domain:"
    $summaryData | Format-Table -AutoSize

    if ($SummaryTsv) {
        try {
            if (-not [System.IO.Path]::IsPathRooted($SummaryTsv)) {
                $SummaryTsv = (Join-Path -Path (Get-Location) -ChildPath $SummaryTsv)
            }

            Export-Tsv -Path $SummaryTsv -InputObject $summaryData
            Write-Host "Summary TSV written to: $SummaryTsv"
        }
        catch {
            Write-Warning "Failed to write summary TSV '$SummaryTsv': $($_.Exception.Message)"
        }
    }
}
