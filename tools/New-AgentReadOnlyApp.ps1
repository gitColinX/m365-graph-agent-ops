#Requires -Version 7.2
<#
.SYNOPSIS
  Plans, and with -Apply creates, a read-only Entra app registration for an AI agent: read-only Microsoft Graph
  permissions (delegated, and a smaller application set), a certificate credential, no client secret. It never
  grants consent. Read-only is not the same as least-privilege; the trade-off is spelled out below.

.DESCRIPTION
  Why a dedicated app: the shared first-party Graph command-line client carries every scope ever consented to it
  in the tenant, so asking for fewer scopes per task does not shrink the token. A dedicated app makes the ceiling
  explicit: its delegated permissions cap what the agent can do as me, and its application permissions cap what
  it can do unattended. See docs/adr-0001-agent-admin-access.md and docs/scopes-and-roles.md.

  The trade-off, plainly. Application permissions are tenant-wide, and the certificate's private key sits in my
  user certificate store. "Non-exportable" only means the key cannot be copied out. Anything running as me, the
  agent included, can still use it to sign in as the app: unattended, with no MFA, and outside Conditional
  Access unless the tenant licenses Conditional Access for workload identities. That cuts against the rest of
  this repo, where the human holds the sign-in. So this script narrows what it can:
    - The application set is smaller than the delegated set. Sites.Read.All (every SharePoint and OneDrive
      file) and UserAuthenticationMethod.Read.All are delegated only by default. Content-reading permissions
      (mail, files, sites, chats, calendars, contacts, authentication methods, BitLocker keys, LAPS passwords)
      are refused for the application set unless -AllowSensitiveApplicationPermissions is passed.
    - The key is created in the TPM by default (Microsoft Platform Crypto Provider), so it is bound to this
      machine. -KeyStorage Software falls back to a non-exportable software key.
    - The certificate lives 3 months by default (at most 12).
    - The service principal is created with appRoleAssignmentRequired = true.
    - Public client flows (device code, username and password) are never switched on for this app.
      -EnableDelegatedPublicClient only adds an http://localhost redirect for an interactive MCP client.
    - The output tells you to alert on and review sign-ins by this service principal.

  Dry run (default): resolves every permission id on the Microsoft Graph (and optionally Exchange Online) service
  principal, refuses any permission that is not read-only, checks that no app with this name exists, and writes
  plan.json. Nothing is created and the REST layer stays read-only.

  -Apply (never run against a tenant in this form; only the dry run is tested):
    1. Creates a self-signed RSA 2048 / SHA-256 certificate in Cert:\CurrentUser\My, TPM-backed by default,
       private key non-exportable.
    2. POSTs the application: single tenant, the read-only requiredResourceAccess, the certificate's public
       key as a keyCredential, no passwordCredentials. If this POST fails, the certificate is removed again.
    3. POSTs the service principal with appRoleAssignmentRequired = true.
    4. Reads both back and checks: permission count, exactly one key credential, zero secrets, single tenant,
       public client flows off, assignment required.
    5. Prints the admin consent URL and the Exchange steps for the people who hold those roles.

  Consent: Cloud Application Administrator and Application Administrator can grant tenant-wide consent for
  delegated permissions, and for application permissions on APIs other than Microsoft Graph. Microsoft Graph
  application permissions need Privileged Role Administrator or Global Administrator. Route the whole app to a
  second person rather than consent to half of your own agent's app yourself.

  Exchange app-only: Exchange.ManageAsApp is only the door. What the app can do in Exchange comes from either
  an Entra role assigned to the service principal (for example Global Reader), or Exchange RBAC: an Exchange
  admin runs New-ServicePrincipal (registering the Entra service principal inside Exchange) and then adds it to
  a role group such as View-Only Organization Management.

.EXAMPLE
  pwsh -File tools/New-AgentReadOnlyApp.ps1 -TenantId contoso.onmicrosoft.com -IncludeExchange
.EXAMPLE
  pwsh -File tools/New-AgentReadOnlyApp.ps1 -TenantId contoso.onmicrosoft.com -IncludeExchange -Apply
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string] $TenantId,
  [string] $DisplayName = 'Agent-ReadOnly',
  [string[]] $DelegatedPermissions = @(
    'User.Read.All', 'Group.Read.All', 'GroupMember.Read.All', 'Directory.Read.All', 'Device.Read.All',
    'DeviceManagementManagedDevices.Read.All', 'DeviceManagementApps.Read.All', 'DeviceManagementConfiguration.Read.All',
    'DeviceManagementServiceConfig.Read.All', 'AuditLog.Read.All', 'Reports.Read.All', 'Policy.Read.All',
    'RoleManagement.Read.Directory', 'UserAuthenticationMethod.Read.All', 'Team.ReadBasic.All', 'Channel.ReadBasic.All',
    'Sites.Read.All', 'Application.Read.All', 'Organization.Read.All'),
  [string[]] $ApplicationPermissions = @(
    'User.Read.All', 'Group.Read.All', 'GroupMember.Read.All', 'Directory.Read.All', 'Device.Read.All',
    'DeviceManagementManagedDevices.Read.All', 'DeviceManagementApps.Read.All', 'DeviceManagementConfiguration.Read.All',
    'DeviceManagementServiceConfig.Read.All', 'AuditLog.Read.All', 'Reports.Read.All', 'Policy.Read.All',
    'RoleManagement.Read.Directory', 'Team.ReadBasic.All', 'Channel.ReadBasic.All',
    'Application.Read.All', 'Organization.Read.All'),
  [switch] $AllowSensitiveApplicationPermissions,
  [switch] $IncludeExchange,
  [switch] $EnableDelegatedPublicClient,
  [ValidateSet('Tpm', 'Software')][string] $KeyStorage = 'Tpm',
  [ValidateRange(1, 12)][int] $CertificateMonths = 3,
  [switch] $Apply,
  [string] $OutDir
)
$ErrorActionPreference = 'Stop'
$graphAppId = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph (first-party resource)
$exoAppId = '00000002-0000-0ff1-ce00-000000000000'     # Office 365 Exchange Online (first-party resource)
$readOnly = '\.(Read|ReadBasic)(\.All|\.Directory)?$'
# Read-only, but reads content or secrets. Tenant-wide and unattended, these are refused for the application set.
$sensitiveAppOnly = '^(Mail|MailboxSettings|Files|Sites|Chat|ChannelMessage|Calendars|Contacts|Notes|OnlineMeetingTranscript|OnlineMeetingRecording|UserAuthenticationMethod|BitlockerKey|DeviceLocalCredential|InformationProtectionContent)\.'

$notReadOnly = @(@($DelegatedPermissions) + @($ApplicationPermissions) | Where-Object { $_ -notmatch $readOnly } | Sort-Object -Unique)
if ($notReadOnly) { throw "Refusing non-read-only permission(s): $($notReadOnly -join ', '). This app is read-only by design; a write app is a separate registration." }
$sensitive = @($ApplicationPermissions | Where-Object { $_ -match $sensitiveAppOnly })
if ($sensitive -and -not $AllowSensitiveApplicationPermissions) {
  throw "Refusing application (app-only) permission(s) that read content or secrets tenant-wide: $($sensitive -join ', '). Keep them delegated, or pass -AllowSensitiveApplicationPermissions for a named job that needs them."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'auth' 'DeviceCodeAuth.psm1')
Import-Module (Join-Path $repoRoot 'lib' 'AgentGraph.psm1')
if (-not $OutDir) { $OutDir = Join-Path $repoRoot 'out' "agent-app-$(Get-Date -Format yyyyMMdd-HHmmss)" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$authProfile = if ($Apply) { 'AppRegistration' } else { 'GraphRead' }
$tok = Get-AgentAccessToken -TenantId $TenantId -AuthProfile $authProfile -CacheOnly
Set-GraphRestContext -AccessToken $tok.AccessToken -AllowWrites:$Apply

function Get-ResourceSp([string] $AppId) {
  $sp = @(Get-GraphPaged -Uri "v1.0/servicePrincipals?`$filter=appId eq '$AppId'&`$select=id,appId,displayName,oauth2PermissionScopes,appRoles")
  if ($sp.Count -ne 1) { throw "Expected one service principal for resource $AppId, found $($sp.Count)." }
  $sp[0]
}

$graphSp = Get-ResourceSp $graphAppId
$access = [System.Collections.Generic.List[object]]::new()
$missing = [System.Collections.Generic.List[string]]::new()
foreach ($perm in $DelegatedPermissions) {
  $d = @($graphSp.oauth2PermissionScopes | Where-Object value -eq $perm) | Select-Object -First 1
  if ($d) { $access.Add([ordered]@{ id = $d.id; type = 'Scope' }) } else { $missing.Add("delegated:$perm") }
}
foreach ($perm in $ApplicationPermissions) {
  $a = @($graphSp.appRoles | Where-Object value -eq $perm) | Select-Object -First 1
  if ($a) { $access.Add([ordered]@{ id = $a.id; type = 'Role' }) } else { $missing.Add("application:$perm") }
}
$required = [System.Collections.Generic.List[object]]::new()
$required.Add([ordered]@{ resourceAppId = $graphAppId; resourceAccess = $access.ToArray() })
if ($IncludeExchange) {
  $exoSp = Get-ResourceSp $exoAppId
  $role = @($exoSp.appRoles | Where-Object value -eq 'Exchange.ManageAsApp') | Select-Object -First 1
  if ($role) { $required.Add([ordered]@{ resourceAppId = $exoAppId; resourceAccess = @([ordered]@{ id = $role.id; type = 'Role' }) }) }
  else { $missing.Add('exchange-application:Exchange.ManageAsApp') }
}
$expectedEntries = ($required | ForEach-Object { @($_.resourceAccess).Count } | Measure-Object -Sum).Sum

$existing = @(Get-GraphPaged -Uri "v1.0/applications?`$filter=displayName eq '$(ConvertTo-ODataLiteral $DisplayName)'&`$select=id,appId,displayName")
$plan = [ordered]@{
  displayName              = $DisplayName
  signInAudience           = 'AzureADMyOrg'
  delegatedPermissions     = $DelegatedPermissions
  applicationPermissions   = $ApplicationPermissions
  exchangeManageAsApp      = [bool]$IncludeExchange
  requiredResourceAccess   = $required.ToArray()
  permissionEntries        = $expectedEntries
  notFoundOnResource       = $missing.ToArray()
  delegatedLocalhostRedirect = [bool]$EnableDelegatedPublicClient
  publicClientFlows        = 'off'
  servicePrincipal         = 'appRoleAssignmentRequired = true'
  credential               = "self-signed certificate, $KeyStorage key, non-exportable, $CertificateMonths months, no client secret"
  appOnlyTradeOff          = 'Anything running as the certificate owner can sign in as this app without MFA. Keep the application set to what a named job needs, and alert on this service principal''s sign-ins.'
  existingAppsWithName     = @($existing | ForEach-Object { $_.appId })
}
$plan | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $OutDir 'plan.json') -Encoding utf8
Write-Output "PLAN app '$DisplayName' (read-only, not least-privilege): $expectedEntries permission entries ($(@($DelegatedPermissions).Count) delegated, $(@($ApplicationPermissions).Count) application$(if ($IncludeExchange) { ', plus Exchange.ManageAsApp' }))."
Write-Output "PLAN credential: $($plan.credential). Public client flows stay off; the service principal requires assignment."
if ($missing.Count) { Write-Output "PLAN not found on the resource (skipped): $($missing -join ', ')" }
if ($existing.Count) {
  Write-Output "STOP an app named '$DisplayName' already exists ($($existing.Count)). Nothing changed. Pick another -DisplayName or review the existing app."
  exit 2
}
if (-not $Apply) {
  Write-Output "DRY RUN. Nothing was created. Plan: $(Join-Path $OutDir 'plan.json'). Re-run with -Apply (needs the AppRegistration sign-in profile)."
  exit 0
}

if (-not $IsWindows) { throw 'Certificate creation uses the Windows certificate store. Run -Apply on Windows.' }
$certParams = @{
  Subject           = "CN=$DisplayName"
  CertStoreLocation = 'Cert:\CurrentUser\My'
  KeyExportPolicy   = 'NonExportable'
  KeyAlgorithm      = 'RSA'
  KeyLength         = 2048
  HashAlgorithm     = 'SHA256'
  NotAfter          = (Get-Date).AddMonths($CertificateMonths)
}
if ($KeyStorage -eq 'Tpm') { $certParams.Provider = 'Microsoft Platform Crypto Provider' } else { $certParams.KeySpec = 'Signature' }
$cert = New-SelfSignedCertificate @certParams
$certPath = "Cert:\CurrentUser\My\$($cert.Thumbprint)"
Write-Output "CERT created in Cert:\CurrentUser\My thumbprint=$($cert.Thumbprint) notAfter=$($cert.NotAfter.ToString('yyyy-MM-dd')) key=$KeyStorage, non-exportable"

$body = [ordered]@{
  displayName            = $DisplayName
  signInAudience         = 'AzureADMyOrg'
  notes                  = 'Read-only app for an AI coding agent. Certificate credential only. Consent by a Global Administrator or Privileged Role Administrator.'
  isFallbackPublicClient = $false
  requiredResourceAccess = $required.ToArray()
  keyCredentials         = @([ordered]@{ type = 'AsymmetricX509Cert'; usage = 'Verify'; key = [Convert]::ToBase64String($cert.RawData); displayName = "CN=$DisplayName" })
}
if ($EnableDelegatedPublicClient) {
  # A redirect for an interactive MCP client. Public client flows (isFallbackPublicClient) stay off: they would
  # allow device code and password sign-ins to an app that also holds application permissions.
  $body.publicClient = [ordered]@{ redirectUris = @('http://localhost') }
}
try {
  $app = Invoke-GraphRest -Method POST -Uri 'v1.0/applications' -Body $body
} catch {
  Remove-Item -LiteralPath $certPath -DeleteKey -ErrorAction SilentlyContinue
  Write-Output "FAIL application POST: $($_.Exception.Message)"
  Write-Output "The certificate was removed again. If the error was a 503 or 504, look for an app named '$DisplayName' before re-running: it may have been created anyway."
  exit 4
}
try {
  $sp = Invoke-GraphRest -Method POST -Uri 'v1.0/servicePrincipals' -Body ([ordered]@{ appId = $app.appId; appRoleAssignmentRequired = $true })
} catch {
  Write-Output "FAIL service principal POST: $($_.Exception.Message)"
  Write-Output "The app exists (appId $($app.appId)) with the certificate $($cert.Thumbprint). Create its service principal by hand with appRoleAssignmentRequired = true, or delete the app and the certificate."
  exit 4
}

# Read-back
$appBack = Invoke-GraphRest -Uri "v1.0/applications/$($app.id)?`$select=id,appId,displayName,signInAudience,requiredResourceAccess,keyCredentials,passwordCredentials,isFallbackPublicClient"
$spBack = Invoke-GraphRest -Uri "v1.0/servicePrincipals/$($sp.id)?`$select=id,appId,displayName,appRoleAssignmentRequired"
$gotEntries = (@($appBack.requiredResourceAccess) | ForEach-Object { @($_.resourceAccess).Count } | Measure-Object -Sum).Sum
$checks = [ordered]@{
  permissionEntries   = ($gotEntries -eq $expectedEntries)
  oneKeyCredential    = (@($appBack.keyCredentials).Count -eq 1)
  noSecrets           = (@($appBack.passwordCredentials).Count -eq 0)
  singleTenant        = ($appBack.signInAudience -eq 'AzureADMyOrg')
  publicClientFlowsOff = ($appBack.isFallbackPublicClient -ne $true)
  servicePrincipal    = ($spBack.appId -eq $app.appId)
  assignmentRequired  = ($spBack.appRoleAssignmentRequired -eq $true)
}
$consentUrl = "https://login.microsoftonline.com/$TenantId/adminconsent?client_id=$($app.appId)"
$result = [ordered]@{
  displayName        = $DisplayName
  tenantId           = $TenantId
  appId              = $app.appId
  applicationId      = $app.id
  servicePrincipalId = $sp.id
  certThumbprint     = $cert.Thumbprint
  certNotAfter       = $cert.NotAfter.ToString('s')
  keyStorage         = $KeyStorage
  readBack           = $checks
  adminConsentUrl    = $consentUrl
  next               = @(
    "Admin consent (Global Administrator or Privileged Role Administrator for Graph application permissions): $consentUrl",
    "Exchange admin, if Exchange.ManageAsApp was included: New-ServicePrincipal -AppId $($app.appId) -ObjectId $($sp.id) -DisplayName '$DisplayName'",
    "Exchange admin, then: Add-RoleGroupMember -Identity 'View-Only Organization Management' -Member $($sp.id) (or assign an Entra role such as Global Reader to the service principal instead)",
    "Graph app-only: Connect-MgGraph -ClientId $($app.appId) -TenantId $TenantId -CertificateThumbprint $($cert.Thumbprint) -NoWelcome",
    "Exchange app-only: Connect-ExchangeOnline -AppId $($app.appId) -CertificateThumbprint $($cert.Thumbprint) -Organization <tenant>.onmicrosoft.com",
    "Monitoring: alert on service principal sign-ins for appId $($app.appId) and review them; anything running as the certificate owner can sign in as this app without MFA.",
    "Rotation: replace the certificate before $($cert.NotAfter.ToString('yyyy-MM-dd')).",
    'If this machine is lost: remove the key credential from the app (or delete the app). The private key never left this machine.'
  )
}
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutDir 'app.json') -Encoding utf8
foreach ($k in $checks.Keys) { Write-Output ("READBACK {0,-20} {1}" -f $k, $(if ($checks[$k]) { 'OK' } else { 'FAILED' })) }
$result.next | ForEach-Object { Write-Output "NEXT $_" }
Write-Output "OUT_DIR=$OutDir"
if ($checks.Values -contains $false) { exit 4 }
