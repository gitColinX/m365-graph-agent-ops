#Requires -Version 7.2
<#
.SYNOPSIS
  Invites one external user as a B2B guest through the Graph PowerShell SDK, with a duplicate check first and
  a read-back after. Dry run by default.

.DESCRIPTION
  1. Hands the cached GuestInvite token to the SDK (Connect-MgGraph -AccessToken).
  2. Looks for an existing account with that mail address. If one exists it reports its type and
     externalUserState and stops, because a second invitation is rarely what anyone wanted.
  3. With -Apply, New-MgInvitation. Then Get-MgUser on the new object: expect userType Guest and
     externalUserState PendingAcceptance.

  The invitation's redeem URL is not printed. It works as a one-time sign-up link; let the invitation email
  carry it, or hand it over through a channel you trust.

  Whether the guest can then open anything depends on more than the invitation: your cross-tenant access
  settings, their tenant's outbound settings, and the sharing settings on the resource. See
  docs/case-studies/b2b-external-sharing-diagnosis.md.

.EXAMPLE
  pwsh -File recipes/New-B2BGuestInvitation.ps1 -TenantId contoso.onmicrosoft.com -Email partner.user@example.com -DisplayName 'Partner User'
.EXAMPLE
  pwsh -File recipes/New-B2BGuestInvitation.ps1 -TenantId contoso.onmicrosoft.com -Email partner.user@example.com -DisplayName 'Partner User' -SendInvitationMessage -Apply
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string] $TenantId,
  [Parameter(Mandatory)][ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')][string] $Email,
  [Parameter(Mandatory)][string] $DisplayName,
  [string] $RedirectUrl = 'https://myapps.microsoft.com',
  [switch] $SendInvitationMessage,
  [switch] $Apply
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'auth' 'DeviceCodeAuth.psm1')
$tok = Get-AgentAccessToken -TenantId $TenantId -AuthProfile GuestInvite -CacheOnly
$ctx = Connect-AgentGraph -AccessToken $tok.AccessToken
Write-Output "Connected as $($ctx.Account)"
Import-Module Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns -ErrorAction Stop

$q = $Email.Replace("'", "''")
$existing = @(Get-MgUser -Filter "mail eq '$q'" -Property Id, UserPrincipalName, UserType, ExternalUserState -All)
if ($existing.Count -gt 0) {
  foreach ($u in $existing) { Write-Output "EXISTS id=$($u.Id) type=$($u.UserType) state=$($u.ExternalUserState)" }
  Write-Output 'STOP an account with this mail address already exists. Nothing changed.'
  exit 2
}
if (-not $Apply) {
  Write-Output "DRY RUN would invite '$DisplayName' <$Email>, redirect $RedirectUrl, send email: $([bool]$SendInvitationMessage). Re-run with -Apply."
  exit 0
}

$inv = New-MgInvitation -InvitedUserEmailAddress $Email -InvitedUserDisplayName $DisplayName -InviteRedirectUrl $RedirectUrl -SendInvitationMessage:$SendInvitationMessage
Write-Output "INVITED status=$($inv.Status) userId=$($inv.InvitedUser.Id) (redeem URL not printed)"
Start-Sleep -Seconds 3
$back = Get-MgUser -UserId $inv.InvitedUser.Id -Property Id, UserPrincipalName, UserType, ExternalUserState, CreatedDateTime
Write-Output "READBACK type=$($back.UserType) state=$($back.ExternalUserState) created=$($back.CreatedDateTime)"
if ($back.UserType -ne 'Guest') { exit 4 }
