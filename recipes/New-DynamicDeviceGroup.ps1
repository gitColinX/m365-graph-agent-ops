#Requires -Version 7.2
<#
.SYNOPSIS
  Creates a dynamic device security group with New-MgGroup -MembershipRule. Dry run by default; read-back after.

.DESCRIPTION
  I used this to build a scoping group for a Windows 10 refresh: the rule below matches Windows devices whose
  OS version starts with 10.0.1, which is every Windows 10 build (10.0.10240 to 10.0.19045). Windows 11 builds
  start at 10.0.22000. Check the result before you target anything at it: registered Windows Server objects
  can also report 10.0.1xxxx.

  1. Hands the cached GroupWrite token to the SDK.
  2. Refuses if a group with this display name already exists.
  3. With -Apply: New-MgGroup with GroupTypes DynamicMembership, rule processing On, mail disabled,
     security enabled. Reads the group back and compares the rule text.
  4. -WaitMinutes polls the member count once a minute; dynamic membership takes a while to evaluate.

  Dynamic groups need Microsoft Entra ID P1 licensing.

.EXAMPLE
  pwsh -File recipes/New-DynamicDeviceGroup.ps1 -TenantId contoso.onmicrosoft.com -DisplayName 'Windows10-Devices-Dynamic'
.EXAMPLE
  pwsh -File recipes/New-DynamicDeviceGroup.ps1 -TenantId contoso.onmicrosoft.com -DisplayName 'Windows10-Devices-Dynamic' -Apply -WaitMinutes 15
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string] $TenantId,
  [Parameter(Mandatory)][string] $DisplayName,
  [string] $MembershipRule = '(device.deviceOSType -eq "Windows") and (device.deviceOSVersion -startsWith "10.0.1")',
  [string] $Description = 'Dynamic device group. Rule-based; do not add members by hand.',
  [ValidateRange(0, 120)][int] $WaitMinutes = 0,
  [switch] $Apply
)
$ErrorActionPreference = 'Stop'
if ($MembershipRule -match '\buser\.') { throw 'This recipe builds device groups. A rule cannot mix user. and device. properties.' }
if ($MembershipRule -notmatch '\bdevice\.') { throw 'The rule does not reference any device. property.' }
$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'auth' 'DeviceCodeAuth.psm1')
$tok = Get-AgentAccessToken -TenantId $TenantId -AuthProfile GroupWrite -CacheOnly
$ctx = Connect-AgentGraph -AccessToken $tok.AccessToken
Write-Output "Connected as $($ctx.Account)"
Import-Module Microsoft.Graph.Groups -ErrorAction Stop

$q = $DisplayName.Replace("'", "''")
$existing = @(Get-MgGroup -Filter "displayName eq '$q'" -Property Id, DisplayName, GroupTypes, MembershipRule -All)
if ($existing.Count -gt 0) {
  foreach ($g in $existing) { Write-Output "EXISTS id=$($g.Id) types=$($g.GroupTypes -join ',') rule=$($g.MembershipRule)" }
  Write-Output 'STOP a group with this name already exists. Nothing changed.'
  exit 2
}
$nick = ($DisplayName -replace '[^A-Za-z0-9]', '')
if (-not $nick) { $nick = 'dyngroup' }
if ($nick.Length -gt 56) { $nick = $nick.Substring(0, 56) }
Write-Output "PLAN group '$DisplayName' mailNickname=$nick"
Write-Output "PLAN rule: $MembershipRule"
if (-not $Apply) { Write-Output 'DRY RUN. Nothing was created. Re-run with -Apply.'; exit 0 }

$g = New-MgGroup -DisplayName $DisplayName -Description $Description -MailEnabled:$false -MailNickname $nick `
  -SecurityEnabled -GroupTypes @('DynamicMembership') -MembershipRule $MembershipRule -MembershipRuleProcessingState 'On'
$back = Get-MgGroup -GroupId $g.Id -Property Id, DisplayName, GroupTypes, MembershipRule, MembershipRuleProcessingState
$ruleOk = ($back.MembershipRule -eq $MembershipRule)
Write-Output "READBACK id=$($back.Id) types=$($back.GroupTypes -join ',') processing=$($back.MembershipRuleProcessingState) ruleMatches=$ruleOk"
if (-not $ruleOk) { exit 4 }

$deadline = (Get-Date).AddMinutes($WaitMinutes)
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 60
  $n = @(Get-MgGroupMember -GroupId $g.Id -All).Count
  Write-Output "$(Get-Date -Format HH:mm) members: $n"
}
