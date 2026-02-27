<#
.SYNOPSIS
Export AD user attributes with flexible search capability.

.DESCRIPTION
Allows lookup by identity or arbitrary attribute using -SearchField.

.EXAMPLE
Export-ADUserAttributes -User jsmith

.EXAMPLE
Export-ADUserAttributes -SearchField uidNumber 1000

.EXAMPLE
Export-ADUserAttributes -SearchField mail user@example.com -Fields SamAccountName,mail
#>

[CmdletBinding(DefaultParameterSetName = "ByUser")]
param(
    [Parameter(
        Mandatory = $false,
        Position = 0,
        ParameterSetName = "ByUser"
    )]
    [string]$User,

    [Parameter(
        Mandatory = $false,
        Position = 0,
        ParameterSetName = "BySearch"
    )]
    [Alias("LookupField")]
    [string]$SearchField,

    [Parameter(
        Mandatory = $false,
        Position = 1,
        ParameterSetName = "BySearch"
    )]
    [Alias("LookupValue")]
    [string]$SearchValue,

    [Parameter(Mandatory = $false)]
    [string[]]$Fields = @(),

    [Parameter(Mandatory = $false)]
    [string]$Domain,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential
)

#
# Normalize parameters
#

if ($SearchField) {
    $LookupField = $SearchField
    $LookupValue = $SearchValue
}

#
# Validation
#

if (-not $User -and -not $SearchField) {
    throw "Specify either -User or -SearchField <field> <value>"
}

if ($SearchField -and -not $SearchValue) {
    throw "Search value required when using -SearchField"
}

#
# Confirm parameter visibility
#

Write-Verbose "ParameterSet: $($PSCmdlet.ParameterSetName)"
Write-Verbose "SearchField: $SearchField"
Write-Verbose "SearchValue: $SearchValue"