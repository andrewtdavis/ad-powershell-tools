<#
.SYNOPSIS
    Expand group membership for members of one or more groups across all domains
    in the forest, automatically selecting the correct domain for each lookup.

.DESCRIPTION
    For each specified group (name, sAMAccountName, or DN, possibly in multiple
    domains):

      - Resolves the group in the correct domain:
          * If a DN is provided, the domain is derived from the DN.
          * Otherwise, the group is looked up in the -Domain parameter's domain
            (or forest-wide if -Domain is omitted).

      - Gets the members of that group (optionally recursively).

      - For each user member, finds ALL groups in the forest that list that
        user's DN in their 'member' attribute. This gives you cross-domain
        group membership without having to manually specify lookup domains.

    Outputs only status messages and (optionally) a summary table.
    Use -OutTsv and -SummaryTsv for machine-readable output.

.PARAMETER Groups
    One or more group identities:
      - Name or SamAccountName (resolved in -Domain if provided)
      - DistinguishedName (CN=...,OU=...,DC=...,DC=...) which may be from
        different domains.

.PARAMETER Domain
    Optional: A domain FQDN (e.g. corehpc.ucsf.edu) used as:
      - The default place to resolve non-DN group identities.
      - The server for initial forest discovery.

    If omitted, forest discovery uses the current logon context.

.PARAMETER IncludeNested
    If set, group membership is expanded recursively.

.PARAMETER OutTsv
    Optional path to write detailed results to a TSV file.

.PARAMETER Summary
    If set, outputs a per-domain summary of memberships.

.PARAMETER SummaryTsv
    Optional path to write summary output to a TSV file.

.EXAMPLE
    .\Get-GroupMemberGroupMembership.ps1 `
        -Groups "My-Group" `
        -Domain "corehpc.ucsf.edu" `
        -OutTsv ".\membership.tsv" `
        -Summary `
        -SummaryTsv ".\membership-summary.tsv"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string[]]$Groups,

    [Parameter(Mandatory = $false)]
    [string]$Domain,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeNested,

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

function Resolve-Group {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,

        [Parameter(Mandatory = $false)]
        [string]$DefaultDomain,

        [Parameter(Mandatory = $true)]
        [hashtable]$DomainMap,

        [Parameter(Mandatory = $true)]
        [string[]]$DomainDCList
    )

    # If this looks like a DN, derive domain from it
    if ($GroupId -match '^.+?,DC=.+') {
        $groupDomain = Get-DomainFromDN -DistinguishedName $GroupId
        $server = Get-ServerForDomain -DomainName $groupDomain -DomainMap $DomainMap
        try {
            return Get-ADGroup -Identity $GroupId -Server $server -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to resolve group DN '$GroupId' in domain '$groupDomain': $($_.Exception.Message)"
            return $null
        }
    }

    # Otherwise, use DefaultDomain if provided
    if ($DefaultDomain) {
        $server = Get-ServerForDomain -DomainName $DefaultDomain -DomainMap $DomainMap
        try {
            # Try identity directly first
            $g = Get-ADGroup -Identity $GroupId -Server $server -ErrorAction SilentlyContinue
            if ($g) { return $g }

            # Fallback to searching by samAccountName or Name
            $g = Get-ADGroup -Server $server -Filter "samAccountName -eq '$GroupId' -or Name -eq '$GroupId'" -ErrorAction SilentlyContinue
            if ($g) { return $g }
        }
        catch {
            Write-Warning "Failed to resolve group '$GroupId' in default domain '$DefaultDomain': $($_.Exception.Message)"
        }
    }

    # Last resort: hunt for group in all domains
    foreach ($dc in $DomainDCList) {
        try {
            $g = Get-ADGroup -Identity $GroupId -Server $dc -ErrorAction SilentlyContinue
            if ($g) { return $g }

            $g = Get-ADGroup -Server $dc -Filter "samAccountName -eq '$GroupId' -or Name -eq '$GroupId'" -ErrorAction SilentlyContinue
            if ($g) { return $g }
        }
        catch { }
    }

    Write-Warning "Unable to resolve group '$GroupId' in any known domain."
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

$allResults    = @()
$totalNonUsers = 0

# Resolve and process each source group
foreach ($groupId in $Groups) {

    $group = Resolve-Group -GroupId $groupId -DefaultDomain $Domain -DomainMap $domainMap -DomainDCList $domainDCList
    if (-not $group) { continue }

    $groupDomain = Get-DomainFromDN -DistinguishedName $group.DistinguishedName
    $groupServer = Get-ServerForDomain -DomainName $groupDomain -DomainMap $domainMap

    Write-Host "Processing group '$($group.SamAccountName)' in domain '$groupDomain' (server: $groupServer)..."

    $memberParams = @{
        Identity    = $group
        Server      = $groupServer
        ErrorAction = 'Stop'
    }
    if ($IncludeNested.IsPresent) { $memberParams['Recursive'] = $true }

    try {
        $members = Get-ADGroupMember @memberParams
    }
    catch {
        Write-Warning "Failed to get members for group '$($group.SamAccountName)': $($_.Exception.Message)"
        continue
    }

    if (-not $members) {
        Write-Host "  No members."
        continue
    }

    $userMembers = $members | Where-Object { $_.objectClass -eq 'user' -or $_.objectClass -eq 'inetOrgPerson' }
    $nonUserCount = $members.Count - $userMembers.Count
    if ($nonUserCount -gt 0) {
        $totalNonUsers += $nonUserCount
        Write-Verbose "Skipping $nonUserCount non-user members in group '$($group.SamAccountName)'."
    }

    foreach ($member in $userMembers) {

        $memberDN     = $member.DistinguishedName
        $memberDomain = Get-DomainFromDN -DistinguishedName $memberDN
        $memberServer = Get-ServerForDomain -DomainName $memberDomain -DomainMap $domainMap

        # Normalize user info (get extra properties) from their "home" domain
        $user = $null
        try {
            $user = Get-ADUser -Server $memberServer -Identity $memberDN -Properties displayName, userPrincipalName -ErrorAction Stop
        }
        catch {
            # Try brute-force by SID across domains if DN lookup fails
            foreach ($dc in $domainDCList) {
                try {
                    $user = Get-ADUser -Server $dc -Identity $member.SID -Properties displayName, userPrincipalName -ErrorAction SilentlyContinue
                    if ($user) { break }
                }
                catch { }
            }
        }

        if (-not $user) {
            Write-Warning "Could not resolve user '$($member.SamAccountName)' in any domain; skipping membership lookup."
            continue
        }

        $userDN        = $user.DistinguishedName
        $escapedUserDN = Escape-LdapFilterValue -Value $userDN

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
                SourceGroupName       = $group.Name
                SourceGroupSam        = $group.SamAccountName
                SourceGroupDN         = $group.DistinguishedName

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
}

if ($totalNonUsers -gt 0) {
    Write-Host "Skipped a total of $totalNonUsers non-user members across all groups."
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