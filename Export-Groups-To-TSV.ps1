 <#
.SYNOPSIS
    Export members of matching AD groups into separate TSV files (DN-derived domain lookup).

.DESCRIPTION
    - Searches a domain + OU (Windows-style) for groups matching a wildcard.
    - Expands group membership (recursive).
    - For each user member:
        * parse DN → get domain → query THAT domain
        * this stops “wrong DC” lookups
    - Only foreignSecurityPrincipal objects are fanned out to all forest domains.
    - Writes ONE TSV per group, but ONLY if the group has at least one resolved member.
    - TSV columns:
        SamAccountName<TAB>UserPrincipalName<TAB>ActiveDirectoryDomainServicesFolder

.PARAMETER GroupPattern
    Wildcard group name pattern (e.g. SERVICE_GRP_NUM0*)

.PARAMETER SearchDomain
    Domain to search for groups (e.g. domain2.corp.local)

.PARAMETER SearchBase
    Windows-style OU path (e.g. "Service/Groups")

.PARAMETER OutputDir
    Directory to write per-group TSVs.

.EXAMPLE
    .\Export-Groups-To-TSV.ps1 `
        -GroupPattern "SERVICE_GRP_NUM0*" `
        -SearchDomain "domain2.corp.local" `
        -SearchBase "Service/Groups" `
        -OutputDir "C:\temp\ad-groups"

.AUTHOR
    Andrew Davis <andrew.davis@gladstone.ucsf.edu>
#>

param(
    [string]$GroupPattern,
    [string]$SearchDomain,
    [string]$SearchBase,
    [string]$OutputDir,
    [switch]$h,
    [switch]$help
)

if ($h -or $help -or -not $GroupPattern -or -not $SearchDomain -or -not $SearchBase -or -not $OutputDir) {
    Write-Host @"
Usage: .\Export-Groups-To-TSV.ps1 -GroupPattern <pattern> -SearchDomain <domain> -SearchBase <ou_path> -OutputDir <dir>

Example:
    .\Export-Groups-To-TSV.ps1 `
        -GroupPattern "SERVICE_GRP_NUM0*" `
        -SearchDomain "domain2.corp.local" `
        -SearchBase "Service/Groups" `
        -OutputDir "C:\temp\ad-groups"
"@
    exit 0
}

Import-Module ActiveDirectory

if (-not (Test-Path -Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

function Convert-ToLdapSearchBase {
    param(
        [Parameter(Mandatory = $true)][string]$SearchDomain,
        [Parameter(Mandatory = $true)][string]$OuPath
    )

    $dcParts = $SearchDomain.Split('.') | ForEach-Object { "DC=$_" }
    $dcDn = $dcParts -join ','

    $ouParts = $OuPath -split '[\\/]' | Where-Object { $_ -ne '' }
    [array]::Reverse($ouParts)
    $ouDn = $ouParts | ForEach-Object { "OU=$_" }
    $ouDn = $ouDn -join ','

    if ($ouDn) { return "$ouDn,$dcDn" } else { return $dcDn }
}

function Get-DomainFromDN {
    param([string]$DN)
    if (-not $DN) { return $null }
    $dcs = [regex]::Matches($DN, 'DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value }
    if ($dcs.Count -gt 0) { return ($dcs -join '.') }
    return $null
}

function Get-ADFolderFromCanonical {
    param([string]$CanonicalName)
    if (-not $CanonicalName) { return "" }
    $parts = $CanonicalName -split '/'
    if ($parts.Count -le 1) { return $CanonicalName }
    return ($parts[0..($parts.Count - 2)] -join '/')
}

function Sanitize-FileName {
    param([string]$Name)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    foreach ($c in $invalid) {
        $Name = $Name -replace [regex]::Escape($c), '_'
    }
    return $Name
}

# Build LDAP base for group search
$ldapSearchBase = Convert-ToLdapSearchBase -SearchDomain $SearchDomain -OuPath $SearchBase

# Get all domains in forest for FSP resolution only
$forest     = Get-ADForest
$domainList = $forest.Domains

Write-Host "Searching domain: $SearchDomain"
Write-Host "LDAP base     : $ldapSearchBase"
Write-Host "Pattern       : $GroupPattern"

$groups = Get-ADGroup -Server $SearchDomain `
                      -SearchBase $ldapSearchBase `
                      -SearchScope Subtree `
                      -Filter "name -like '$GroupPattern'" `
                      -ErrorAction SilentlyContinue

if (-not $groups) {
    Write-Warning "No groups found."
    exit 1
}

foreach ($grp in $groups) {

    Write-Host "→ Processing group: $($grp.Name)"

    # get members from the group’s domain
    $members = Get-ADGroupMember -Server $SearchDomain -Identity $grp -Recursive -ErrorAction SilentlyContinue

    if (-not $members) {
        Write-Warning "   Group '$($grp.Name)' has no members — skipping file."
        continue
    }

    $rows = @()

    foreach ($m in $members) {

        $sam    = ""
        $upn    = ""
        $folder = ""

        if ($m.objectClass -eq 'user' -and $m.DistinguishedName) {
            $memberDomain = Get-DomainFromDN $m.DistinguishedName

            if ($memberDomain) {
                # query the domain that owns this DN
                $u = Get-ADUser -Server $memberDomain -Identity $m.DistinguishedName -Properties Enabled,UserPrincipalName,CanonicalName -ErrorAction SilentlyContinue
                if ($u -and $u.Enabled) {
                    $sam    = $u.SamAccountName
                    $upn    = $u.UserPrincipalName
                    $folder = Get-ADFolderFromCanonical $u.CanonicalName
                }
                else {
                    # couldn't find it in the domain from DN — log as unresolved
                    $sam    = $m.Name
                    $upn    = ""
                    $folder = "UNRESOLVED (DN domain: $memberDomain)"
                }
            }
            else {
                # DN has no DC= parts? very odd — record as unresolved
                $sam    = $m.Name
                $upn    = ""
                $folder = "UNRESOLVED (no DN domain)"
            }
        }
        elseif ($m.objectClass -eq 'foreignSecurityPrincipal' -and $m.SID) {
            $resolved = $false
            foreach ($tryDomain in $domainList) {
                $u = Get-ADUser -Server $tryDomain -Identity $m.SID -Properties Enabled,UserPrincipalName,CanonicalName -ErrorAction SilentlyContinue
                if ($u -and $u.Enabled) {
                    $sam    = $u.SamAccountName
                    $upn    = $u.UserPrincipalName
                    $folder = Get-ADFolderFromCanonical $u.CanonicalName
                    $resolved = $true
                    break
                }
            }
            if (-not $resolved) {
                $sam    = $m.Name
                $upn    = ""
                $folder = "UNRESOLVED-FSP"
            }
        }
        else {
            # groups/computers/other
            $sam    = $m.Name
            $upn    = ""
            $folder = "NON-USER"
        }

        $rows += [PSCustomObject]@{
            SamAccountName     = $sam
            UserPrincipalName  = $upn
            ADSFolder          = $folder
        }
    }

    # remove exact duplicates
    $rows = $rows | Sort-Object SamAccountName, UserPrincipalName, ADSFolder -Unique

    # if after resolving everything we still have 0 rows, don't write the file
    if ($rows.Count -eq 0) {
        Write-Warning "   Group '$($grp.Name)' resolved to 0 members — skipping file."
        continue
    }

    # write file now that we know it's non-empty
    $safeName = Sanitize-FileName $grp.Name
    $outFile  = Join-Path $OutputDir "$safeName.tsv"

    "SamAccountName`tUserPrincipalName`tActiveDirectoryDomainServicesFolder" | Set-Content -Path $outFile -Encoding UTF8

    foreach ($r in $rows) {
        "$($r.SamAccountName)`t$($r.UserPrincipalName)`t$($r.ADSFolder)" | Add-Content -Path $outFile -Encoding UTF8
    }

    Write-Host "   wrote $($rows.Count) members -> $outFile"
}

Write-Host "Done. Finished processing $($groups.Count) groups."
