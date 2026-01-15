 <#
.SYNOPSIS
    Lists the SamAccountName of active members of the specified group.

.DESCRIPTION
    This lists the SamAccountName of all active members of a group specitified from STDIN. It supports cross-domain
    looksups and will sort them alphabetically.

.EXAMPLE
    .\Get-ActiveGroupMembers.ps1 "Domain Users"

#>


Import-Module ActiveDirectory

if ($args[0]) {
    $JDGIGroupName = $args[0]
} else {
    $JDGIGroupName = Read-Host "No Group name Specified, Please enter one:"
}

# Get all domains in the forest and make a lookup
$forest = Get-ADForest
$domainList = $forest.Domains      # e.g. domain1.corp.local, domain2.corp.local
$domainSet  = @{}
foreach ($d in $domainList) {
    $domainSet[$d.ToLower()] = $d
}

# helper: pull DNS domain out of a DN
function Get-DnsDomainFromDN {
    param($DN)
    # grab DC= parts, join with dots
    $dcs = ([regex]::Matches($DN, 'DC=([^,]+)')).Groups | Where-Object { $_.Value -ne '' } | ForEach-Object { $_.Value }
    if ($dcs.Count -gt 0) {
        return ($dcs -join '.')
    }
    return $null
}

$results = @()

# first: find the group(s) in any domain
foreach ($groupDomain in $domainList) {
    $groups = Get-ADGroup -Server $groupDomain -Filter "name -like '$JDGIGroupName'" -ErrorAction SilentlyContinue
    if (-not $groups) { continue }

    foreach ($grp in $groups) {
        # get members from the domain that owns the group
        $members = Get-ADGroupMember -Server $groupDomain -Identity $grp -Recursive -ErrorAction SilentlyContinue

        foreach ($m in $members) {

            # 1) normal users/groups from other domains will have a DN we can parse
            if ($m.objectClass -eq 'user') {
                $memberDomain = Get-DnsDomainFromDN $m.DistinguishedName
                if ($memberDomain -and $domainSet.ContainsKey($memberDomain.ToLower())) {
                    $u = Get-ADUser -Server $domainSet[$memberDomain.ToLower()] -Identity $m.DistinguishedName -Properties Enabled -ErrorAction SilentlyContinue
                } else {
                    # fallback: try all domains
                    $u = $null
                    foreach ($tryDomain in $domainList) {
                        $u = Get-ADUser -Server $tryDomain -Identity $m.DistinguishedName -Properties Enabled -ErrorAction SilentlyContinue
                        if ($u) { break }
                    }
                }

                if ($u -and $u.Enabled) {
                    $results += $u.SamAccountName
                }
            }
            elseif ($m.objectClass -eq 'foreignSecurityPrincipal') {
                # 2) FSPs only have a SID we can resolve; try it in each domain
                foreach ($tryDomain in $domainList) {
                    $u = Get-ADUser -Server $tryDomain -Identity $m.SID -Properties Enabled -ErrorAction SilentlyContinue
                    if ($u -and $u.Enabled) {
                        $results += $u.SamAccountName
                        break
                    }
                }
            }
            # you could add 'group' here too if you want to walk cross-domain groups differently
        }
    }
}

$results | Sort-Object -Unique
