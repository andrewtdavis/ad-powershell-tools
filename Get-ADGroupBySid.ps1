 <#
.SYNOPSIS
    Resolve one or more group SIDs anywhere in the Active Directory forest.

.DESCRIPTION
    For each given SID (S-1-5-21-...), this script:
      - Discovers all domains in the forest (optionally starting from -Domain).
      - Tries to resolve the SID as a group against each domain controller
        in the forest using Get-ADGroup -Identity $Sid.
      - Stops on first successful match per SID.
      - Emits a small object with:
            Sid
            Name
            SamAccountName
            DistinguishedName
            Domain

    By default, it prints a table. You can also write results to a TSV file
    with -OutTsv.

.PARAMETER Sids
    One or more group SIDs in SDDL form (e.g. 'S-1-5-21-...').

.PARAMETER Domain
    Optional domain FQDN (e.g. example.com) to use as:
      - The initial server for forest discovery (Get-ADForest -Server).
    If omitted, the current logon context is used.

.PARAMETER OutTsv
    Optional path to write detailed results to a TSV file.

.EXAMPLE
    .\Get-ADGroupBySid.ps1 -Sids 'S-1-5-21-1234567890-1111-2222-3333-555'

.EXAMPLE
    .\Get-ADGroupBySid.ps1 `
        -Sids 'S-1-5-21-1234567890-1111-2222-3333-555','S-1-5-21-1234567890-1111-2222-3333-666' `
        -Domain 'example.com' `
        -OutTsv '.\groups-by-sid.tsv'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string[]]$Sids,

    [Parameter(Mandatory = $false)]
    [string]$Domain,

    [Parameter(Mandatory = $false)]
    [string]$OutTsv
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
    $domainList = @()    # list of DC hostnames (for brute-force lookups)

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

#endregion helper functions

try {
    Ensure-ADModule
}
catch {
    Write-Error $_
    return
}

# Discover forest domains / DCs
try {
    $forestMap = Get-ForestDomainMap -Server $Domain
}
catch {
    Write-Error "Failed to discover forest/domain information: $($_.Exception.Message)"
    return
}

$domainDCList = $forestMap.DomainDCList

if (-not $domainDCList -or $domainDCList.Count -eq 0) {
    Write-Error "No domain controllers discovered in the forest. Cannot continue."
    return
}

$results = @()

foreach ($sid in $Sids) {

    # Validate / normalize SID
    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid)
    }
    catch {
        Write-Warning "Value '$sid' is not a valid SID; skipping."
        continue
    }

    Write-Host "Resolving SID $sid across forest..."

    $group = $null

    foreach ($dc in $domainDCList) {
        try {
            # Get-ADGroup Identity supports SID, but you must target the right DC/domain
            $group = Get-ADGroup -Identity $sidObj -Server $dc -ErrorAction SilentlyContinue
            if ($group) {
                break
            }
        }
        catch {
            # Ignore and try next DC
        }
    }

    if (-not $group) {
        Write-Warning "SID $sid not found as a group in any domain."
        continue
    }

    $domain = Get-DomainFromDN -DistinguishedName $group.DistinguishedName

    $results += [PSCustomObject]@{
        Sid               = $sid
        Name              = $group.Name
        SamAccountName    = $group.SamAccountName
        DistinguishedName = $group.DistinguishedName
        Domain            = $domain
    }
}

if (-not $results -or $results.Count -eq 0) {
    Write-Warning "No groups resolved from the supplied SIDs."
    return
}

Write-Host ""
Write-Host "Resolved groups:"
$results |
    Sort-Object Domain, Name |
    Format-Table -AutoSize

if ($OutTsv) {
    try {
        if (-not [System.IO.Path]::IsPathRooted($OutTsv)) {
            $OutTsv = (Join-Path -Path (Get-Location) -ChildPath $OutTsv)
        }

        Export-Tsv -Path $OutTsv -InputObject $results
        Write-Host "TSV written to: $OutTsv"
    }
    catch {
        Write-Warning "Failed to write TSV '$OutTsv': $($_.Exception.Message)"
    }
}
