<#
List all trusts and show domain + forest creation dates
using direct ADSI lookup of "creationTime".
#>

function Get-DomainCreationTime {
    param([string]$DomainFqdn)

    try {
        # RootDSE for the target domain
        $root = [ADSI]"LDAP://$DomainFqdn/RootDSE"
        $nc   = $root.defaultNamingContext
        $cfg  = $root.configurationNamingContext

        # Domain NC
        $domainNc = [ADSI]"LDAP://$DomainFqdn/$nc"
        $domainCreated = $domainNc.creationTime

        # Forest (Configuration NC)
        $forestNc = [ADSI]"LDAP://$DomainFqdn/$cfg"
        $forestCreated = $forestNc.creationTime

        return [pscustomobject]@{
            Domain             = $DomainFqdn
            DomainCreated      = $domainCreated
            ForestCreated      = $forestCreated
        }
    }
    catch {
        return [pscustomobject]@{
            Domain             = $DomainFqdn
            DomainCreated      = $null
            ForestCreated      = $null
        }
    }
}

Import-Module ActiveDirectory

# First show the local domain
$local = Get-ADDomain
Write-Output (Get-DomainCreationTime -DomainFqdn $local.DNSRoot)

# Then enumerate trusts
Get-ADTrust -Filter * | Sort-Object Name | ForEach-Object {
    Write-Output (Get-DomainCreationTime -DomainFqdn $_.Name)
}