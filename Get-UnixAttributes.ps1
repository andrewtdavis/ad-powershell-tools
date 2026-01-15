<#
.SYNOPSIS
    Retrieve RFC2307 (Unix) attributes for an Active Directory user.

.DESCRIPTION
    Looks up an Active Directory user by a provided identity value and outputs
    commonly used RFC2307 / Unix attributes:

      - uid
      - uidNumber
      - gidNumber
      - gecos
      - unixHomeDirectory

    The lookup attribute is controlled by -IdentityType:
      - EmailAddress   (Get-ADUser -Filter { EmailAddress -eq <value> })
      - Mail           (Get-ADUser -Filter { mail -eq <value> })
      - UserPrincipalName
      - SamAccountName

    Output is a single PSCustomObject.

.PARAMETER Identity
    The identity value used to locate the user.

.PARAMETER IdentityType
    The Active Directory attribute used for lookup.

.PARAMETER Server
    Optional domain controller or domain DNS name used for the query.

.EXAMPLE
    PS C:\> .\Get-UnixAttributes.ps1 -Identity alice@example.com -IdentityType Mail

.EXAMPLE
    PS C:\> .\Get-UnixAttributes.ps1 -Identity alice@example.com -IdentityType EmailAddress -Server dc01.example.com

.OUTPUTS
    System.Management.Automation.PSCustomObject

.NOTES
    Requires the ActiveDirectory module (RSAT: Active Directory tools).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('Email','UPN','SamAccountName')]
    [ValidateNotNullOrEmpty()]
    [string]$Identity,

    [Parameter(Mandatory = $false)]
    [ValidateSet('EmailAddress','Mail','UserPrincipalName','SamAccountName')]
    [string]$IdentityType = 'Mail',

    [Parameter(Mandatory = $false)]
    [string]$Server
)

begin {
    try {
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            throw "ActiveDirectory module not found. Install RSAT: Active Directory tools."
        }
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Error $_.Exception.Message
        throw
    }
}

process {
    $filter = $null
    switch ($IdentityType) {
        'EmailAddress'     { $filter = { EmailAddress -eq $Identity } }
        'Mail'             { $filter = { mail -eq $Identity } }
        'UserPrincipalName'{ $filter = { UserPrincipalName -eq $Identity } }
        'SamAccountName'   { $filter = { SamAccountName -eq $Identity } }
    }

    Write-Verbose "Querying Active Directory user by $IdentityType: $Identity"

    $params = @{
        Filter      = $filter
        Properties  = @('uid','uidNumber','gidNumber','unixHomeDirectory','gecos','UserPrincipalName','SamAccountName','Name')
        ErrorAction = 'Stop'
    }
    if ($Server) { $params.Server = $Server }

    $user = Get-ADUser @params
    if (-not $user) {
        Write-Error "User not found for $IdentityType='$Identity'."
        return
    }

    [pscustomobject]@{
        Name              = $user.Name
        SamAccountName    = $user.SamAccountName
        UserPrincipalName = $user.UserPrincipalName
        uid               = $user.uid
        uidNumber         = $user.uidNumber
        gidNumber         = $user.gidNumber
        unixHomeDirectory = $user.unixHomeDirectory
        gecos             = $user.gecos
    }
}
