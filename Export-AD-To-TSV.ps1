<#
.SYNOPSIS
    Export Active Directory group membership to TSV files, expanding groups recursively across trusted domains.

.DESCRIPTION
    This script finds AD groups matching a name pattern under a specified OU (search base) in a given domain,
    then recursively expands membership while handling:
      - nested groups
      - cross-domain users (based on DN/DC components)
      - circular group membership (cycle-safe)

    Output is written as TSV (tab-separated) so that commas in canonical names/paths are preserved.

.PARAMETER GroupPattern
    AD group name pattern, e.g. "APP_*" or "LINUX-ADMINS*".

.PARAMETER SearchDomain
    Primary AD domain to query, e.g. "example.corp.local".

.PARAMETER SearchBase
    OU path (slash or backslash form) under which to search for the groups, e.g. "Infrastructure/Groups".
    This is converted to an LDAP DN using the provided SearchDomain.

.PARAMETER OutputDir
    Directory to which TSV files will be written. Created if it does not exist.

.PARAMETER Full
    Overwrite existing TSV files, even if they already exist.

.PARAMETER Log
    Optional path to a log file. If provided, the script appends to that file and writes a run header
    (timestamp, script name, arguments). The file is opened once with read-sharing so it can be tailed.

.EXAMPLE
    .\Export-AD-To-TSV.ps1 `
        -GroupPattern "APP_*" `
        -SearchDomain "example.corp.local" `
        -SearchBase "Infrastructure/Groups" `
        -OutputDir ".\exports" `
        -Verbose

.NOTES
    - Requires the ActiveDirectory module.
    - Recursive expansion is cycle-safe.

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$GroupPattern,
    [Parameter(Mandatory = $true)]
    [string]$SearchDomain,
    [Parameter(Mandatory = $true)]
    [string]$SearchBase,
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,
    [switch]$Full,
    [string]$Log
)

# -------- logging helpers --------
$LogWriter = $null
if ($Log) {
    try {
        # append, allow readers
        $fs = [System.IO.File]::Open($Log, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $LogWriter = New-Object System.IO.StreamWriter($fs)
        $LogWriter.AutoFlush = $true

        $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $cmdLine = $MyInvocation.Line
        $LogWriter.WriteLine("================================================================")
        $LogWriter.WriteLine("Run start : $ts")
        $LogWriter.WriteLine("Script    : Export-AD-To-TSV.ps1")
        $LogWriter.WriteLine("Command   : $cmdLine")
        $LogWriter.WriteLine("================================================================")
    } catch {
        Write-Warning "Could not open log file '$Log' for writing: $($_.Exception.Message)"
    }
}
function Write-Log {
    param([string]$Message)
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    if ($PSBoundParameters.ContainsKey('Verbose')) {
        Write-Verbose $Message
    }
    if ($LogWriter) {
        $LogWriter.WriteLine("[$ts] $Message")
    }
}
function Close-Log {
    if ($LogWriter) {
        $LogWriter.Flush()
        $LogWriter.Dispose()
    }
}

try {
    function Convert-ToLdapSearchBase {
        param($SearchDomain, $OuPath)
        $dcParts = $SearchDomain.Split('.') | ForEach-Object { "DC=$_" }
        $dcDn = $dcParts -join ','
        $ouParts = $OuPath -split '[\\/]' | Where-Object { $_ }
        [array]::Reverse($ouParts)
        $ouDn = $ouParts | ForEach-Object { "OU=$_" }
        $ouDn = $ouDn -join ','
        if ($ouDn) { "$ouDn,$dcDn" } else { $dcDn }
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
        ($parts[0..($parts.Count - 2)] -join '/')
    }

    function Sanitize-FileName {
        param([string]$Name)
        $invalid = [IO.Path]::GetInvalidFileNameChars()
        foreach ($c in $invalid) {
            $Name = $Name -replace [regex]::Escape($c), '_'
        }
        $Name
    }

    function Should-SkipFileVerbose {
        param(
            [string]$Path,
            [switch]$Full,
            [string]$Reason = "exists"
        )
        if ($Full) { return $false }
        if (-not (Test-Path $Path)) { return $false }
        Write-Log "Skipping '$Path' ($Reason)."
        return $true
    }

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir | Out-Null
    }

    Import-Module ActiveDirectory

    $ldapBase   = Convert-ToLdapSearchBase $SearchDomain $SearchBase
    $forest     = Get-ADForest
    $domainList = $forest.Domains

    function Get-AdGroupMembersRecursive {
        param(
            [Microsoft.ActiveDirectory.Management.ADGroup]$GroupObj,
            [string]$PreferredServer,
            [string[]]$DomainList,
            [hashtable]$Visited
        )

        $results = @()
        $gKey = $GroupObj.DistinguishedName
        if ($Visited.ContainsKey($gKey)) {
            return @()
        }
        $Visited[$gKey] = $true

        $members = $null
        try {
            $members = Get-ADGroupMember -Server $PreferredServer -Identity $GroupObj -ErrorAction Stop
        } catch {
            foreach ($d in $DomainList) {
                try {
                    $members = Get-ADGroupMember -Server $d -Identity $GroupObj -ErrorAction Stop
                    if ($members) { break }
                } catch {}
            }
        }

        if (-not $members) { return @() }

        foreach ($m in $members) {
            if ($m.objectClass -eq 'user' -and $m.DistinguishedName) {
                $userDomain = Get-DomainFromDN $m.DistinguishedName
                if ($userDomain) {
                    $u = Get-ADUser -Server $userDomain -Identity $m.DistinguishedName -Properties Enabled,UserPrincipalName,CanonicalName -ErrorAction SilentlyContinue
                    if ($u -and $u.Enabled) {
                        $results += [pscustomobject]@{
                            SamAccountName    = $u.SamAccountName
                            UserPrincipalName = $u.UserPrincipalName
                            ADSFolder         = Get-ADFolderFromCanonical $u.CanonicalName
                        }
                    } else {
                        $results += [pscustomobject]@{
                            SamAccountName    = $m.Name
                            UserPrincipalName = ""
                            ADSFolder         = "UNRESOLVED (user disabled or missing)"
                        }
                    }
                } else {
                    $results += [pscustomobject]@{
                        SamAccountName    = $m.Name
                        UserPrincipalName = ""
                        ADSFolder         = "UNRESOLVED (no DN domain)"
                    }
                }
            }
            elseif ($m.objectClass -eq 'group') {
                $childDomain = $null
                if ($m.DistinguishedName) { $childDomain = Get-DomainFromDN $m.DistinguishedName }
                if (-not $childDomain) { $childDomain = $PreferredServer }
                $childGroup = Get-ADGroup -Server $childDomain -Identity $m.DistinguishedName -ErrorAction SilentlyContinue
                if ($childGroup) {
                    $results += Get-AdGroupMembersRecursive -GroupObj $childGroup -PreferredServer $childDomain -DomainList $DomainList -Visited $Visited
                }
            }
            elseif ($m.objectClass -eq 'foreignSecurityPrincipal' -and $m.SID) {
                $resolved = $false
                foreach ($d in $DomainList) {
                    $u = Get-ADUser -Server $d -Identity $m.SID -Properties Enabled,UserPrincipalName,CanonicalName -ErrorAction SilentlyContinue
                    if ($u -and $u.Enabled) {
                        $results += [pscustomobject]@{
                            SamAccountName    = $u.SamAccountName
                            UserPrincipalName = $u.UserPrincipalName
                            ADSFolder         = Get-ADFolderFromCanonical $u.CanonicalName
                        }
                        $resolved = $true
                        break
                    }
                }
                if (-not $resolved) {
                    $results += [pscustomobject]@{
                        SamAccountName    = $m.Name
                        UserPrincipalName = ""
                        ADSFolder         = "UNRESOLVED-FSP"
                    }
                }
            }
            else {
                $results += [pscustomobject]@{
                    SamAccountName    = $m.Name
                    UserPrincipalName = ""
                    ADSFolder         = "NON-USER"
                }
            }
        }

        return $results
    }

    Write-Log "Searching for AD groups matching '$GroupPattern' in '$SearchDomain' under '$SearchBase'..."
    $adGroups = Get-ADGroup -Server $SearchDomain -SearchBase $ldapBase -SearchScope Subtree -Filter "name -like '$GroupPattern'" -ErrorAction SilentlyContinue
    if (-not $adGroups) {
        Write-Log "No AD groups found for pattern '$GroupPattern' under $SearchBase."
        return
    }

    foreach ($grp in $adGroups) {
        Write-Log "Processing AD group '$($grp.Name)'"
        $outFile = Join-Path $OutputDir ("ad-" + (Sanitize-FileName $grp.Name) + ".tsv")
        if (Should-SkipFileVerbose -Path $outFile -Full:$Full -Reason "file already exists") {
            continue
        }

        $groupDomain = Get-DomainFromDN $grp.DistinguishedName
        if (-not $groupDomain) { $groupDomain = $SearchDomain }

        $visited = @{}
        $members = Get-AdGroupMembersRecursive -GroupObj $grp -PreferredServer $groupDomain -DomainList $domainList -Visited $visited
        if ($members.Count -gt 0) {
            $lines = @("SamAccountName`tUserPrincipalName`tActiveDirectoryDomainServicesFolder")
            $lines += $members | ForEach-Object {
                "$($_.SamAccountName)`t$($_.UserPrincipalName)`t$($_.ADSFolder)"
            }
            $lines | Set-Content -Path $outFile -Encoding UTF8
            Write-Log "Wrote $outFile"
        } else {
            Write-Log "Group '$($grp.Name)' had no members."
        }
    }

    Write-Log "AD export done."
}
finally {
    Close-Log
}