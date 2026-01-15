<#
.SYNOPSIS
    Create or update Unix / RFC2307 attributes on an AD user.

.DESCRIPTION
    This script looks up an Active Directory user by email address and ensures
    the core Unix/RFC2307 attributes are populated:

        - uid
        - uidNumber
        - gidNumber
        - gecos
        - unixHomeDirectory

    For each attribute:
      1. If you pass a value on the command line, that value is used.
      2. Else, if the user already has a value in AD, that existing value is used.
      3. Else, you are prompted for a value (unless -NonInteractive, in which case it errors).

    The script also:
      - Shows a preview of what will be applied and marks each field as (NEW) or (MODIFIED).
      - Special-cases the 'uid' attribute: if the user has a different value or multiple values,
        it clears 'uid' first and then adds the single desired value. This avoids uid lists.

.PARAMETER Email
    The email address used to locate the AD user. This is required.

.PARAMETER UnixUsername
    Value to set for 'uid'. If omitted, the existing AD value is used, or you will be prompted.

.PARAMETER UidNumber
    Value to set for 'uidNumber'. If omitted, the existing AD value is used, or you will be prompted.

.PARAMETER GidNumber
    Value to set for 'gidNumber'. If omitted, the existing AD value is used, or you will be prompted.

.PARAMETER Gecos
    Value to set for 'gecos'. If omitted, the existing AD value is used, or you will be prompted.

.PARAMETER UnixHomeDirectory
    Value to set for 'unixHomeDirectory'. If omitted, the existing AD value is used, or you will be prompted.

.PARAMETER NonInteractive
    If supplied, the script will NOT prompt for missing values and will error instead.
    Useful for automation / pipelines.

.EXAMPLE
    PS C:\> .\Set-UnixAttributes.ps1 -Email alice@example.com
    Looks up the user, pulls current values from AD, and prompts for anything missing.

.EXAMPLE
    PS C:\> .\Set-UnixAttributes.ps1 -Email bob@example.com -UnixHomeDirectory "/home/bob"
    Updates only the home directory (and will prompt for anything else missing in AD).

.EXAMPLE
    PS C:\> .\Set-UnixAttributes.ps1 -Email svc@example.com -UnixUsername svcacct -UidNumber 20010 -GidNumber 20010 -Gecos "Service Account" -UnixHomeDirectory "/srv/svcacct" -NonInteractive
    Fully specifies all values; runs without prompts. Good for CI / automation.

.PARAMETER EmailAttribute
    Active Directory attribute used to locate the user by email address.
    Common values are: mail, EmailAddress.

.PARAMETER Server
    Optional domain controller or domain DNS name used for the query and updates.

.NOTES
    - Requires the ActiveDirectory module (RSAT).

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [string]$Email,

    [Parameter(Mandatory = $false)]
    [ValidateSet('mail','EmailAddress')]
    [string]$EmailAttribute = 'mail',

    [Parameter(Mandatory = $false)]
    [string]$Server,

    [string]$UnixUsername,        # maps to 'uid'
    [string]$UidNumber,           # maps to 'uidNumber'
    [string]$GidNumber,           # maps to 'gidNumber'
    [string]$Gecos,               # maps to 'gecos'
    [string]$UnixHomeDirectory,   # maps to 'unixHomeDirectory'

    [switch]$NonInteractive       # if set, we error instead of prompting
)

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

Write-Verbose "Looking up user by $EmailAttribute: $Email"

$ldapFilter = "($EmailAttribute=$Email)"
$getParams = @{ LDAPFilter = $ldapFilter; Properties = @('uid','uidNumber','gidNumber','gecos','unixHomeDirectory','SamAccountName'); ErrorAction = 'Stop' }
if ($Server) { $getParams.Server = $Server }

$user = Get-ADUser @getParams
if (-not $user) {
    Write-Error "User lookup failed for $EmailAttribute='$Email'."
    return
}

Write-Verbose "Found AD account: $($user.SamAccountName)"

# --- helpers ---

function Get-RequiredValue {
    param(
        [string]$Name,
        [string]$CliValue,
        [string]$ExistingValue,
        [switch]$NonInteractive
    )

    if ($CliValue) {
        return $CliValue
    }

    if ($ExistingValue) {
        return $ExistingValue
    }

    if ($NonInteractive) {
        throw "Missing required attribute '$Name' and running non-interactive."
    }

    $v = Read-Host "Enter value for $Name"
    if (-not $v) {
        throw "Missing required attribute '$Name'."
    }
    return $v
}

function Get-StatusLabel {
    param(
        [string]$Attr,
        [string]$FinalValue,
        [object]$CurrentValue
    )

    # no current value at all
    if ($null -eq $CurrentValue -or $CurrentValue -eq "") {
        return "(NEW)"
    }

    # current value is multivalued
    if ($CurrentValue -is [array]) {
        # if it's exactly 1 value and matches, it's unchanged
        if ($CurrentValue.Count -eq 1 -and $CurrentValue[0] -eq $FinalValue) {
            return ""
        } else {
            return "(MODIFIED)"
        }
    }

    # single value, compare
    if ($CurrentValue -ne $FinalValue) {
        return "(MODIFIED)"
    }

    return ""
}

# --- gather final values (what we want to enforce) ---

$finalUid               = Get-RequiredValue -Name "uid (Unix username)"     -CliValue $UnixUsername      -ExistingValue ($user.uid -join "") -NonInteractive:$NonInteractive
$finalUidNumber         = Get-RequiredValue -Name "uidNumber"               -CliValue $UidNumber         -ExistingValue $user.uidNumber      -NonInteractive:$NonInteractive
$finalGidNumber         = Get-RequiredValue -Name "gidNumber"               -CliValue $GidNumber         -ExistingValue $user.gidNumber      -NonInteractive:$NonInteractive
$finalGecos             = Get-RequiredValue -Name "gecos"                   -CliValue $Gecos             -ExistingValue $user.gecos          -NonInteractive:$NonInteractive
$finalUnixHomeDirectory = Get-RequiredValue -Name "unixHomeDirectory"       -CliValue $UnixHomeDirectory -ExistingValue $user.unixHomeDirectory -NonInteractive:$NonInteractive

# --- preview with (NEW)/(MODIFIED) ---

Write-Information -InformationAction Continue "Final attribute values to enforce:"
Write-Information -InformationAction Continue ("  uid:               {0} {1}" -f $finalUid,               (Get-StatusLabel "uid"               $finalUid               $user.uid))
Write-Information -InformationAction Continue ("  uidNumber:         {0} {1}" -f $finalUidNumber,         (Get-StatusLabel "uidNumber"         $finalUidNumber         $user.uidNumber))
Write-Information -InformationAction Continue ("  gidNumber:         {0} {1}" -f $finalGidNumber,         (Get-StatusLabel "gidNumber"         $finalGidNumber         $user.gidNumber))
Write-Information -InformationAction Continue ("  gecos:             {0} {1}" -f $finalGecos,             (Get-StatusLabel "gecos"             $finalGecos             $user.gecos))
Write-Information -InformationAction Continue ("  unixHomeDirectory: {0} {1}" -f $finalUnixHomeDirectory, (Get-StatusLabel "unixHomeDirectory" $finalUnixHomeDirectory $user.unixHomeDirectory))
Write-Information -InformationAction Continue ""

if (-not $NonInteractive) {
    $confirm = Read-Host "If correct, press Y to continue"
    if ($confirm -notin @("Y","y")) {
        Write-Host "Unconfirmed, exiting."
        exit 1
    }
}

# --- build AD update ---

$replace = @{
    uidNumber          = $finalUidNumber
    gidNumber          = $finalGidNumber
    gecos              = $finalGecos
    unixHomeDirectory  = $finalUnixHomeDirectory
}

$clear = @()
$add   = @{}

$currentUid = $user.uid  # can be null/string/array

$needToClearUid = $false

if ($null -ne $currentUid) {
    if ($currentUid -is [array] -and $currentUid.Count -gt 1) {
        # multiple values -> you said we should clean that up
        $needToClearUid = $true
    }
    elseif ($currentUid -ne $finalUid) {
        # single but different -> replace
        $needToClearUid = $true
    }
}
# else no current uid -> we can just set it in -Replace

if ($needToClearUid) {
    $clear += "uid"
    $add["uid"] = $finalUid
} else {
    # no need to clear first, just include in replace
    $replace["uid"] = $finalUid
}

# --- write to AD ---

if ($clear.Count -gt 0 -and $add.Count -gt 0) {
    Set-ADUser -Identity $user -Clear $clear -Replace $replace -Add $add
} else {
    Set-ADUser -Identity $user -Replace $replace
}

Write-Information -InformationAction Continue "`nResult:"
Get-ADUser -Identity $user -Properties uid,uidNumber,gidNumber,gecos,unixHomeDirectory |
    Select-Object Name, UserPrincipalName, uid, uidNumber, gidNumber, gecos, unixHomeDirectory
