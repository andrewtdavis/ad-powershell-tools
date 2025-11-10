 param(
    [Parameter(Mandatory = $true)]
    [string]$Email,

    [string]$UnixUsername,        # maps to 'uid'
    [string]$UidNumber,           # maps to 'uidNumber'
    [string]$GidNumber,           # maps to 'gidNumber'
    [string]$Gecos,               # maps to 'gecos'
    [string]$UnixHomeDirectory,   # maps to 'unixHomeDirectory'

    [switch]$NonInteractive       # if set, we error instead of prompting
)

Import-Module ActiveDirectory

Write-Host "Looking up user by email: $Email"

# adjust 'mail' to 'EmailAddress' if your environment uses that
$user = Get-ADUser -Filter { mail -eq $Email } -Properties uid,uidNumber,gidNumber,gecos,unixHomeDirectory
if (-not $user) {
    Write-Host "User lookup failed. Please check email address."
    exit 1
}

Write-Host "Found AD account: $($user.SamAccountName)"
Write-Host ""

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

Write-Host "Final attribute values to enforce:"
Write-Host ("  uid:               {0} {1}" -f $finalUid,               (Get-StatusLabel "uid"               $finalUid               $user.uid))
Write-Host ("  uidNumber:         {0} {1}" -f $finalUidNumber,         (Get-StatusLabel "uidNumber"         $finalUidNumber         $user.uidNumber))
Write-Host ("  gidNumber:         {0} {1}" -f $finalGidNumber,         (Get-StatusLabel "gidNumber"         $finalGidNumber         $user.gidNumber))
Write-Host ("  gecos:             {0} {1}" -f $finalGecos,             (Get-StatusLabel "gecos"             $finalGecos             $user.gecos))
Write-Host ("  unixHomeDirectory: {0} {1}" -f $finalUnixHomeDirectory, (Get-StatusLabel "unixHomeDirectory" $finalUnixHomeDirectory $user.unixHomeDirectory))
Write-Host ""

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

Write-Host "`nResult:"
Get-ADUser -Identity $user -Properties uid,uidNumber,gidNumber,gecos,unixHomeDirectory |
    Select-Object Name, UserPrincipalName, uid, uidNumber, gidNumber, gecos, unixHomeDirectory
