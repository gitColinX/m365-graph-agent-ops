#Requires -Version 7.2
<#
.SYNOPSIS
  New-hire cloud onboarding as a series of PASS / FAIL gates. Read-only by default; -Apply performs the writes,
  and every write is followed by a read-back gate.

.DESCRIPTION
  Gates, in order. A FAIL stops the run so a half-onboarded account is obvious.
    1. SYNC      The account exists in Entra ID (for hybrid tenants, directory sync has propagated it).
                 -SyncWaitMinutes polls once a minute.
    2. LOCATION  usageLocation is set. Licensing fails without it, because it decides which services are
                 legally available in that country. -Apply sets it, then reads it back.
    3. SEATS     subscribedSkus shows a free seat of the SKU (enabled prepaid units minus consumed units).
    4. LICENSE   POST /users/{id}/assignLicense with explicit addLicenses and removeLicenses arrays, then
                 licenseDetails read-back including service plan provisioning status.
    5. MFA       Optional: pre-register a mobile phone method (POST authentication/phoneMethods) so first
                 sign-in can complete MFA registration. Needs an authentication admin role.
    6. MAILBOX   Optional: with an Exchange Online session already connected, wait until the recipient is a
                 UserMailbox. Get-Recipient first, because it sees every recipient type.

  I standardized on the REST assignLicense call because it needs only the Graph token, behaves the same in
  every session, and makes the add and remove sets explicit. Set-MgUserLicense does the same job when the
  Microsoft.Graph.Users.Actions module is loaded.

  Use fictitious values when testing: phone numbers from the +1 555 0100 to 0199 range.

.EXAMPLE
  pwsh -File recipes/Invoke-OnboardingGates.ps1 -TenantId contoso.onmicrosoft.com -UserPrincipalName new.hire@contoso.onmicrosoft.com -SkuPartNumber SPE_E3
.EXAMPLE
  pwsh -File recipes/Invoke-OnboardingGates.ps1 -TenantId contoso.onmicrosoft.com -UserPrincipalName new.hire@contoso.onmicrosoft.com `
    -SkuPartNumber SPE_E3 -MobilePhone '+1 5555550123' -SyncWaitMinutes 30 -Apply
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string] $TenantId,
  [Parameter(Mandatory)][string] $UserPrincipalName,
  [Parameter(Mandatory)][string] $SkuPartNumber,
  [string[]] $RemoveSkuPartNumber = @(),
  [ValidatePattern('^[A-Z]{2}$')][string] $UsageLocation = 'US',
  [ValidatePattern('^\+\d{1,3} \d{4,14}$')][string] $MobilePhone,
  [ValidateRange(0, 120)][int] $SyncWaitMinutes = 0,
  [switch] $CheckMailbox,
  [ValidateRange(0, 120)][int] $MailboxWaitMinutes = 0,
  [switch] $Apply
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'auth' 'DeviceCodeAuth.psm1')
Import-Module (Join-Path $repoRoot 'lib' 'AgentGraph.psm1')
$tok = Get-AgentAccessToken -TenantId $TenantId -AuthProfile Onboarding -CacheOnly
Set-GraphRestContext -AccessToken $tok.AccessToken -AllowWrites:$Apply

$gates = [System.Collections.Generic.List[object]]::new()
function Set-Gate([string] $Name, [string] $Result, [string] $Detail) {
  $gates.Add([pscustomobject]@{ Gate = $Name; Result = $Result; Detail = $Detail })
  Write-Output ("{0,-9} {1,-6} {2}" -f $Name, $Result, $Detail)
}
function Stop-Gates { Write-Output ''; $gates | Format-Table -AutoSize | Out-String -Width 200 | Write-Output; exit 1 }
$upnQ = ConvertTo-ODataLiteral $UserPrincipalName

# 1. SYNC
$user = $null
$deadline = (Get-Date).AddMinutes($SyncWaitMinutes)
do {
  $hits = @(Get-GraphPaged -Uri "v1.0/users?`$filter=userPrincipalName eq '$upnQ'&`$select=id,userPrincipalName,accountEnabled,onPremisesSyncEnabled,usageLocation")
  if ($hits.Count -eq 1) { $user = $hits[0]; break }
  if ((Get-Date) -lt $deadline) { Start-Sleep -Seconds 60 }
} while ((Get-Date) -lt $deadline)
if (-not $user) { Set-Gate 'SYNC' 'FAIL' "No Entra account for $UserPrincipalName yet."; Stop-Gates }
Set-Gate 'SYNC' 'PASS' "id=$($user.id) synced=$([bool](Get-PropValue $user 'onPremisesSyncEnabled')) enabled=$($user.accountEnabled)"

# 2. LOCATION
$loc = [string](Get-PropValue $user 'usageLocation')
if ($loc) {
  Set-Gate 'LOCATION' 'PASS' "usageLocation=$loc"
} elseif (-not $Apply) {
  Set-Gate 'LOCATION' 'WOULD' "set usageLocation=$UsageLocation"
} else {
  Invoke-GraphRest -Method PATCH -Uri "v1.0/users/$($user.id)" -Body @{ usageLocation = $UsageLocation } | Out-Null
  $back = Invoke-GraphRest -Uri "v1.0/users/$($user.id)?`$select=usageLocation"
  if ($back.usageLocation -eq $UsageLocation) { Set-Gate 'LOCATION' 'PASS' "set and read back: $UsageLocation" } else { Set-Gate 'LOCATION' 'FAIL' "read-back shows '$($back.usageLocation)'"; Stop-Gates }
}

# 3. SEATS
$skus = @(Get-GraphPaged -Uri 'v1.0/subscribedSkus?$select=skuId,skuPartNumber,prepaidUnits,consumedUnits')
$sku = @($skus | Where-Object skuPartNumber -eq $SkuPartNumber) | Select-Object -First 1
if (-not $sku) { Set-Gate 'SEATS' 'FAIL' "SKU $SkuPartNumber is not in this tenant."; Stop-Gates }
$free = [int]$sku.prepaidUnits.enabled - [int]$sku.consumedUnits
$current = @(Get-GraphPaged -Uri "v1.0/users/$($user.id)/licenseDetails?`$select=skuId,skuPartNumber,servicePlans")
$hasIt = [bool]($current | Where-Object skuId -eq $sku.skuId)
if ($hasIt) { Set-Gate 'SEATS' 'PASS' "user already holds $SkuPartNumber" }
elseif ($free -gt 0) { Set-Gate 'SEATS' 'PASS' "$free free seat(s) of $SkuPartNumber" }
else { Set-Gate 'SEATS' 'FAIL' "no free seats of $SkuPartNumber ($($sku.consumedUnits) of $($sku.prepaidUnits.enabled) used)"; Stop-Gates }

# 4. LICENSE
$removeIds = @(foreach ($r in $RemoveSkuPartNumber) {
    $x = @($skus | Where-Object skuPartNumber -eq $r) | Select-Object -First 1
    if (-not $x) { throw "SKU to remove '$r' is not in this tenant." }
    $x.skuId
  })
if ($hasIt -and -not $removeIds) {
  Set-Gate 'LICENSE' 'PASS' 'already assigned'
} elseif (-not $Apply) {
  Set-Gate 'LICENSE' 'WOULD' "assignLicense add=$SkuPartNumber remove=$($RemoveSkuPartNumber -join ',')"
} else {
  $body = @{ addLicenses = @(if (-not $hasIt) { @{ skuId = $sku.skuId; disabledPlans = @() } }); removeLicenses = @($removeIds) }
  Invoke-GraphRest -Method POST -Uri "v1.0/users/$($user.id)/assignLicense" -Body $body | Out-Null
  Start-Sleep -Seconds 5
  $after = @(Get-GraphPaged -Uri "v1.0/users/$($user.id)/licenseDetails?`$select=skuId,skuPartNumber,servicePlans")
  $got = @($after | Where-Object skuId -eq $sku.skuId) | Select-Object -First 1
  $stillHasRemoved = @($after | Where-Object { $removeIds -contains $_.skuId })
  if ($got -and -not $stillHasRemoved) {
    $pending = @($got.servicePlans | Where-Object { $_.provisioningStatus -notin 'Success', 'Disabled' } | ForEach-Object { "$($_.servicePlanName)=$($_.provisioningStatus)" })
    Set-Gate 'LICENSE' 'PASS' "read back $SkuPartNumber; plans not yet provisioned: $(if ($pending) { $pending -join ', ' } else { 'none' })"
  } else {
    Set-Gate 'LICENSE' 'FAIL' 'licenseDetails read-back does not match the request'; Stop-Gates
  }
}

# 5. MFA pre-registration
if ($MobilePhone) {
  $phones = @(Get-GraphPaged -Uri "v1.0/users/$($user.id)/authentication/phoneMethods")
  if (@($phones | Where-Object phoneType -eq 'mobile').Count -gt 0) {
    Set-Gate 'MFA' 'PASS' 'a mobile phone method is already registered'
  } elseif (-not $Apply) {
    Set-Gate 'MFA' 'WOULD' 'register the mobile phone method'
  } else {
    Invoke-GraphRest -Method POST -Uri "v1.0/users/$($user.id)/authentication/phoneMethods" -Body @{ phoneNumber = $MobilePhone; phoneType = 'mobile' } | Out-Null
    $phones = @(Get-GraphPaged -Uri "v1.0/users/$($user.id)/authentication/phoneMethods")
    if (@($phones | Where-Object phoneType -eq 'mobile').Count -gt 0) { Set-Gate 'MFA' 'PASS' 'mobile phone method registered and read back' } else { Set-Gate 'MFA' 'FAIL' 'phone method not visible on read-back'; Stop-Gates }
  }
} else { Set-Gate 'MFA' 'SKIP' 'no -MobilePhone given' }

# 6. MAILBOX
if ($CheckMailbox) {
  if (-not (Get-Command Get-Recipient -ErrorAction SilentlyContinue)) { Set-Gate 'MAILBOX' 'FAIL' 'no Exchange Online session in this process (Connect-AgentExchange first)'; Stop-Gates }
  $deadline = (Get-Date).AddMinutes($MailboxWaitMinutes)
  $type = $null
  do {
    $rcp = Get-Recipient -Identity $UserPrincipalName -ErrorAction SilentlyContinue
    $type = if ($rcp) { [string]$rcp.RecipientTypeDetails } else { $null }
    if ($type -eq 'UserMailbox') { break }
    if ((Get-Date) -lt $deadline) { Start-Sleep -Seconds 60 }
  } while ((Get-Date) -lt $deadline)
  if ($type -eq 'UserMailbox') { Set-Gate 'MAILBOX' 'PASS' 'recipient is a UserMailbox' } else { Set-Gate 'MAILBOX' 'FAIL' "recipient type is '$type'" }
} else { Set-Gate 'MAILBOX' 'SKIP' 'no -CheckMailbox' }

Write-Output ''
$gates | Format-Table -AutoSize | Out-String -Width 200 | Write-Output
if (@($gates | Where-Object Result -eq 'FAIL').Count) { exit 1 }
