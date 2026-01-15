<#
.SYNOPSIS
  Enumerate domain controllers for one or many domains, with optional site-based sorting.

.EXAMPLE
  .\Get-DomainControllers.ps1 -Domains "domain1.net,domain2.net"

.EXAMPLE
  .\Get-DomainControllers.ps1 -Domains "domain1.net,domain2.net" -SortBySite
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Domains,

    [switch]$SortBySite
)

# Normalize comma-separated domain strings → unique clean list
$DomainList = @()
foreach ($d in $Domains) {
    $DomainList += ($d -split ",") |
                   ForEach-Object { $_.Trim() } |
                   Where-Object { $_ }
}
$DomainList = $DomainList | Select-Object -Unique

# Ensure AD module is available
try {
    if (-not (Get-Module ActiveDirectory -ErrorAction SilentlyContinue)) {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
}
catch {
    Write-Error "Could not load the ActiveDirectory module."
    return
}

$AllResults = @()

foreach ($Domain in $DomainList) {

    try {
        $adDomain = Get-ADDomain -Server $Domain -ErrorAction Stop
        $dnsRoot  = $adDomain.DNSRoot
    }
    catch {
        Write-Warning "Failed to resolve or query domain '$Domain'. Skipping."
        continue
    }

    try {
        $dcs = Get-ADDomainController -Filter * -Server $dnsRoot -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to enumerate DCs for '$dnsRoot'. Skipping."
        continue
    }

    foreach ($dc in $dcs) {

        $fqdn = $dc.HostName
        $site = $dc.Site

        # Collect IPs
        $ips = @()
        if ($dc.IPv4Address) { $ips += $dc.IPv4Address }
        if ($dc.IPv6Address) { $ips += $dc.IPv6Address }

        # DNS lookup fallback
        if (-not $ips) {
            try {
                $ips = [System.Net.Dns]::GetHostAddresses($fqdn) |
                       Where-Object { $_.AddressFamily -in 'InterNetwork','InterNetworkV6' } |
                       ForEach-Object { $_.IPAddressToString }
            }
            catch { }
        }

        if (-not $ips) { $ips = "<no IP found>" }

        $AllResults += [PSCustomObject]@{
            Domain = $dnsRoot
            Site   = $site
            DC_FQDN = $fqdn
            IP      = ($ips -join ", ")
        }
    }
}

# Sorting logic
if ($SortBySite) {
    $Sorted = $AllResults | Sort-Object Site, Domain, DC_FQDN
} else {
    $Sorted = $AllResults | Sort-Object Domain, DC_FQDN
}

$Sorted | Format-Table -AutoSize
return $Sorted