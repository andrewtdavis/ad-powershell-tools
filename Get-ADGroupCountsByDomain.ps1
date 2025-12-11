 <#
.SYNOPSIS
    Summarise group counts (by scope) for one or more domains in an AD forest.

.DESCRIPTION
    For each specified domain, this script counts:
      - Total number of groups
      - Number of Domain Local groups
      - Number of Global groups
      - Number of Universal groups

    By default (with no parameters), it queries the current forest and all of
    its domains.

    You can optionally:
      - Target a specific forest (via -Forest)
      - Restrict the domains to a subset (via -Domains)
      - Supply alternate credentials (via -Credential)

.PARAMETER Forest
    Optional forest root or DC/DNS name to use for forest discovery, e.g.:
        corp.example.com
        dc01.corp.example.com

    If omitted and -Domains is not provided, the current forest is used.

.PARAMETER Domains
    Optional list of domain DNS names to query, e.g.:
        child1.corp.example.com
        child2.corp.example.com

    If omitted, all domains from the specified (or current) forest are used.

.PARAMETER Credential
    Optional PSCredential to use when querying the forest and domains.
    Useful when querying a different forest, e.g.:
        $cred = Get-Credential
        -Credential $cred

.EXAMPLE
    .\Get-ADGroupCountsByDomain.ps1

    Queries the current forest, discovers all domains, and prints a table with
    group counts by scope.

.EXAMPLE
    .\Get-ADGroupCountsByDomain.ps1 -Forest 'corp.example.com'

    Uses corp.example.com as the forest root, discovers all domains in that
    forest, and prints group counts for each domain.

.EXAMPLE
    .\Get-ADGroupCountsByDomain.ps1 -Domains 'child1.corp.example.com','child2.corp.example.com'

    Only queries the specified domains.

.EXAMPLE
    $cred = Get-Credential
    .\Get-ADGroupCountsByDomain.ps1 -Forest 'otherforest.example.net' -Credential $cred

    Uses alternate credentials to query a different forest.
#>

[CmdletBinding()]
param(
    [string]
    $Forest,

    [string[]]
    $Domains,

    [System.Management.Automation.PSCredential]
    $Credential
)

begin {
    # Ensure the ActiveDirectory module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "The ActiveDirectory module is not installed or not available on this system."
    }

    Import-Module ActiveDirectory -ErrorAction Stop
}

process {
    # If no domains explicitly provided, discover them from the forest
    if (-not $Domains -or $Domains.Count -eq 0) {
        Write-Verbose "No domains specified; discovering domains from forest."

        try {
            if ($Forest) {
                if ($Credential) {
                    $forestObj = Get-ADForest -Server $Forest -Credential $Credential -ErrorAction Stop
                } else {
                    $forestObj = Get-ADForest -Server $Forest -ErrorAction Stop
                }
            } else {
                if ($Credential) {
                    # When using Credential without explicit Forest, we still need a server;
                    # you can adjust this if you want a different discovery mechanism.
                    $forestObj = Get-ADForest -Credential $Credential -ErrorAction Stop
                } else {
                    $forestObj = Get-ADForest -ErrorAction Stop
                }
            }

            $Domains = $forestObj.Domains
        }
        catch {
            Write-Error "Failed to discover forest domains: $($_.Exception.Message)"
            return
        }
    }

    if (-not $Domains -or $Domains.Count -eq 0) {
        Write-Warning "No domains to query."
        return
    }

    $results = @()

    foreach ($domain in $Domains) {
        Write-Verbose "Querying domain '$domain' for groups..."

        try {
            if ($Credential) {
                $groups = Get-ADGroup -Server $domain -Credential $Credential -Filter * -Properties GroupScope -ErrorAction Stop
            } else {
                $groups = Get-ADGroup -Server $domain -Filter * -Properties GroupScope -ErrorAction Stop
            }
        }
        catch {
            Write-Warning "Failed to query domain '$domain': $($_.Exception.Message)"
            continue
        }

        $total       = $groups.Count
        $domainLocal = ($groups | Where-Object { $_.GroupScope -eq 'DomainLocal' }).Count
        $global      = ($groups | Where-Object { $_.GroupScope -eq 'Global' }).Count
        $universal   = ($groups | Where-Object { $_.GroupScope -eq 'Universal' }).Count

        $results += [PSCustomObject]@{
            Domain      = $domain
            TotalGroups = $total
            DomainLocal = $domainLocal
            Global      = $global
            Universal   = $universal
        }
    }

    if ($results.Count -gt 0) {
        $results |
            Sort-Object Domain |
            Format-Table -AutoSize
    } else {
        Write-Warning "No results to display."
    }
}
