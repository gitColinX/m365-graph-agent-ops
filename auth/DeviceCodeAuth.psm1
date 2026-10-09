#Requires -Version 7.2
<#
.SYNOPSIS
  OAuth 2.0 device authorization grant (RFC 8628) against Microsoft Entra ID, built for an AI agent's
  non-interactive shell. The human completes sign-in, MFA and Conditional Access in their own browser.

.DESCRIPTION
  - Request-DeviceCode POSTs to /oauth2/v2.0/devicecode. The device_code is kept in memory as a SecureString
    and never written to disk or printed: together with the public client id it can redeem the token.
  - Wait-DeviceCodeToken polls /oauth2/v2.0/token at the server-given interval and honors
    authorization_pending, slow_down (+5 seconds, RFC 8628 section 3.5), authorization_declined,
    access_denied, expired_token, bad_verification_code and the expires_in deadline.
  - offline_access is never requested. A scope list that contains it is refused. If a refresh token comes
    back anyway it is dropped, not stored.
  - Only the access token is cached, encrypted with DPAPI for the current Windows user. The cache expires by
    file age (default 50 minutes, under the 60 to 90 minute default access token lifetime) and by the
    expires_in the token endpoint returned, whichever comes first. The token itself is never parsed:
    Microsoft says clients should treat access tokens as opaque.
  - Connect-AgentGraph hands the token to Connect-MgGraph -AccessToken (SecureString).
    Connect-AgentExchange hands it to Connect-ExchangeOnline -AccessToken.

  DPAPI protects the cache from other Windows users. It does not protect it from anything running as me,
  which includes the agent. The real controls are the short cache life, my approval of production writes
  before they run, and what the token can do: my directory roles with the shared client, or a dedicated app's
  permissions.
#>

Set-StrictMode -Version Latest

# Microsoft first-party public clients. Public, documented application ids, not secrets.
$script:GraphCliClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'      # Microsoft Graph Command Line Tools (Graph PowerShell SDK)
$script:ExoPowerShellClientId = 'fb78d390-0c51-40cd-8e17-fdbfab77341b' # Exchange Online PowerShell (ExchangeOnlineManagement V3)
$script:LoginBase = 'https://login.microsoftonline.com'
$script:DeviceCodeGrant = 'urn:ietf:params:oauth:grant-type:device_code'

# One named profile per kind of job. Tools ask for a profile, never for an ad hoc scope list.
# Note: with the shared Graph CLI client the token carries every scope ever consented to that client, not just
# these, so a token from a "read" profile can still write whatever was consented. See docs/scopes-and-roles.md.
# The profiles document intent, keep one cache file per purpose, and become a real boundary with a dedicated app.
$script:AuthProfiles = [ordered]@{
  GraphRead       = @{ ClientId = $script:GraphCliClientId; Resource = 'https://graph.microsoft.com'; Write = $false
                       Scopes = @('User.Read.All', 'Group.Read.All', 'GroupMember.Read.All', 'Device.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'Application.Read.All', 'Policy.Read.All') }
  IntuneRead      = @{ ClientId = $script:GraphCliClientId; Resource = 'https://graph.microsoft.com'; Write = $false
                       Scopes = @('DeviceManagementManagedDevices.Read.All', 'DeviceManagementApps.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementServiceConfig.Read.All', 'AuditLog.Read.All', 'Device.Read.All', 'User.Read.All') }
  IntuneAppWrite  = @{ ClientId = $script:GraphCliClientId; Resource = 'https://graph.microsoft.com'; Write = $true
                       Scopes = @('DeviceManagementApps.ReadWrite.All') }
  AppRoleWrite    = @{ ClientId = $script:GraphCliClientId; Resource = 'https://graph.microsoft.com'; Write = $true
                       Scopes = @('AppRoleAssignment.ReadWrite.All', 'User.Read.All', 'GroupMember.Read.All', 'Application.Read.All') }
  AppRegistration = @{ ClientId = $script:GraphCliClientId; Resource = 'https://graph.microsoft.com'; Write = $true
                       Scopes = @('Application.ReadWrite.All') }
  Onboarding      = @{ ClientId = $script:GraphCliClientId; Resource = 'https://graph.microsoft.com'; Write = $true
                       Scopes = @('User.ReadWrite.All', 'Organization.Read.All', 'UserAuthenticationMethod.ReadWrite.All') }
  GuestInvite     = @{ ClientId = $script:GraphCliClientId; Resource = 'https://graph.microsoft.com'; Write = $true
                       Scopes = @('User.Invite.All', 'User.Read.All') }
  GroupWrite      = @{ ClientId = $script:GraphCliClientId; Resource = 'https://graph.microsoft.com'; Write = $true
                       Scopes = @('Group.ReadWrite.All') }
  Exchange        = @{ ClientId = $script:ExoPowerShellClientId; Resource = 'https://outlook.office365.com'; Write = $true
                       Scopes = @('.default') }
}

$script:AuthTransport = $null
$script:AuthSleeper = { param([double]$Seconds) Start-Sleep -Milliseconds ([int][math]::Ceiling($Seconds * 1000)) }
$script:AuthClock = { [datetimeoffset]::UtcNow }

#region hooks and transport -----------------------------------------------------------------------

function Set-DeviceAuthTestHook {
  <#
  .SYNOPSIS
    Test seam. Replaces the HTTP transport, the sleep function and the clock. $null restores the defaults.
  #>
  [CmdletBinding()]
  param([scriptblock] $Transport, [scriptblock] $Sleeper, [scriptblock] $Clock)
  $script:AuthTransport = $Transport
  $script:AuthSleeper = if ($Sleeper) { $Sleeper } else { { param([double]$Seconds) Start-Sleep -Milliseconds ([int][math]::Ceiling($Seconds * 1000)) } }
  $script:AuthClock = if ($Clock) { $Clock } else { { [datetimeoffset]::UtcNow } }
}

function Invoke-DefaultAuthHttp {
  param([hashtable] $Request)
  if ($env:M365AGENTOPS_OFFLINE -eq '1') {
    throw 'Network calls are disabled in this process (M365AGENTOPS_OFFLINE=1).'
  }
  $r = Invoke-WebRequest -Method $Request.Method -Uri $Request.Uri -Headers $Request.Headers -Body $Request.Body `
    -ContentType $Request.ContentType -SkipHttpErrorCheck -ErrorAction Stop
  [pscustomobject]@{ StatusCode = [int]$r.StatusCode; Headers = @{}; Content = [string]$r.Content }
}

function Invoke-AuthPost {
  param([string] $Uri, [hashtable] $Form)
  $pairs = foreach ($k in ($Form.Keys | Sort-Object)) {
    '{0}={1}' -f [uri]::EscapeDataString([string]$k), [uri]::EscapeDataString([string]$Form[$k])
  }
  $req = @{
    Method      = 'POST'
    Uri         = $Uri
    Headers     = @{ Accept = 'application/json' }
    Body        = ($pairs -join '&')
    ContentType = 'application/x-www-form-urlencoded'
  }
  $resp = if ($script:AuthTransport) { & $script:AuthTransport $req } else { Invoke-DefaultAuthHttp -Request $req }
  $json = $null
  if (-not [string]::IsNullOrWhiteSpace([string]$resp.Content)) {
    try { $json = $resp.Content | ConvertFrom-Json -Depth 20 } catch { $json = $null }
  }
  [pscustomobject]@{ StatusCode = [int]$resp.StatusCode; Json = $json }
}

function Get-JsonField {
  param($Object, [string] $Name)
  if ($null -eq $Object) { return $null }
  $p = $Object.PSObject.Properties[$Name]
  if ($p) { return $p.Value }
  $null
}

#endregion

#region profiles and validation -------------------------------------------------------------------

function Get-AgentAuthProfile {
  <#
  .SYNOPSIS
    Lists the auth profiles, or returns one by name.
  #>
  [CmdletBinding()]
  param([string] $Name)
  if (-not $Name) {
    return $script:AuthProfiles.Keys | ForEach-Object {
      $p = $script:AuthProfiles[$_]
      [pscustomobject]@{ Name = $_; ClientId = $p.ClientId; Resource = $p.Resource; Write = $p.Write; Scopes = ($p.Scopes -join ' ') }
    }
  }
  if (-not $script:AuthProfiles.Contains($Name)) {
    throw "Unknown auth profile '$Name'. Valid profiles: $($script:AuthProfiles.Keys -join ', ')."
  }
  $p = $script:AuthProfiles[$Name]
  [pscustomobject]@{
    Name     = $Name
    ClientId = $p.ClientId
    Resource = $p.Resource
    Write    = $p.Write
    Scopes   = @($p.Scopes | ForEach-Object { "$($p.Resource)/$_" })
  }
}

function Assert-NoOfflineAccess {
  param([string[]] $Scope)
  # Split every element on whitespace: a single space-separated string is also a valid scope list.
  $each = @($Scope | ForEach-Object { [string]$_ -split '\s+' } | Where-Object { $_ })
  if (@($each | Where-Object { $_ -match '(^|/)offline_access$' }).Count -gt 0) {
    throw 'offline_access is not allowed here. This flow caches a short-lived access token only and never asks for a refresh token.'
  }
}

function Assert-TenantId {
  param([string] $TenantId)
  if ($TenantId -in 'common', 'organizations', 'consumers') {
    throw "Name the tenant explicitly (GUID or verified domain). '$TenantId' is not allowed."
  }
  if ($TenantId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' -and $TenantId -notmatch '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') {
    throw "TenantId '$TenantId' is not a GUID or a domain name."
  }
}

#endregion

#region RFC 8628 ----------------------------------------------------------------------------------

function Request-DeviceCode {
  <#
  .SYNOPSIS
    Starts a device authorization request. Returns the user code to show the human; keeps device_code in memory.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $TenantId,
    [Parameter(Mandatory)][string] $ClientId,
    [Parameter(Mandatory)][string[]] $Scope
  )
  Assert-TenantId -TenantId $TenantId
  Assert-NoOfflineAccess -Scope $Scope
  $r = Invoke-AuthPost -Uri "$script:LoginBase/$TenantId/oauth2/v2.0/devicecode" -Form @{ client_id = $ClientId; scope = ($Scope -join ' ') }
  $userCode = Get-JsonField $r.Json 'user_code'
  $deviceCode = Get-JsonField $r.Json 'device_code'
  if ($r.StatusCode -ne 200 -or -not $userCode -or -not $deviceCode) {
    throw "Device code request failed: HTTP $($r.StatusCode) $(Get-JsonField $r.Json 'error') $(Get-JsonField $r.Json 'error_description')".Trim()
  }
  $interval = [int](Get-JsonField $r.Json 'interval')
  if ($interval -le 0) { $interval = 5 }
  $expires = [int](Get-JsonField $r.Json 'expires_in')
  if ($expires -le 0) { $expires = 900 }
  $uri = Get-JsonField $r.Json 'verification_uri'
  if (-not $uri) { $uri = 'https://microsoft.com/devicelogin' }
  [pscustomobject]@{
    UserCode        = [string]$userCode
    DeviceCode      = (ConvertTo-SecureString -String ([string]$deviceCode) -AsPlainText -Force)
    VerificationUri = [string]$uri
    ExpiresIn       = $expires
    Interval        = $interval
  }
}

function ConvertTo-AccessTokenResult {
  param($Json)
  $at = [string](Get-JsonField $Json 'access_token')
  $granted = [string](Get-JsonField $Json 'scope')
  [pscustomobject]@{
    AccessToken           = (ConvertTo-SecureString -String $at -AsPlainText -Force)
    ExpiresIn             = [int](Get-JsonField $Json 'expires_in')
    GrantedScopes         = @(if ($granted) { $granted -split ' ' | Where-Object { $_ } })
    RefreshTokenDiscarded = [bool](Get-JsonField $Json 'refresh_token')
  }
}

function Wait-DeviceCodeToken {
  <#
  .SYNOPSIS
    Polls the token endpoint until the human finishes sign-in, declines, or the code expires.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $TenantId,
    [Parameter(Mandatory)][string] $ClientId,
    [Parameter(Mandatory)] $DeviceCodeResponse
  )
  Assert-TenantId -TenantId $TenantId
  $interval = [int]$DeviceCodeResponse.Interval
  if ($interval -le 0) { $interval = 5 }
  $deadline = (& $script:AuthClock).AddSeconds([int]$DeviceCodeResponse.ExpiresIn)
  $deviceCode = [System.Net.NetworkCredential]::new('', $DeviceCodeResponse.DeviceCode).Password
  $tokenUri = "$script:LoginBase/$TenantId/oauth2/v2.0/token"
  while ($true) {
    & $script:AuthSleeper $interval
    if ((& $script:AuthClock) -ge $deadline) {
      throw 'The device code expired before sign-in was completed. Start a new sign-in.'
    }
    $r = Invoke-AuthPost -Uri $tokenUri -Form @{ grant_type = $script:DeviceCodeGrant; client_id = $ClientId; device_code = $deviceCode }
    if ($r.StatusCode -eq 200 -and (Get-JsonField $r.Json 'access_token')) {
      return (ConvertTo-AccessTokenResult -Json $r.Json)
    }
    $err = [string](Get-JsonField $r.Json 'error')
    $desc = [string](Get-JsonField $r.Json 'error_description')
    if ($desc.Length -gt 300) { $desc = $desc.Substring(0, 300) }
    if ($err -eq 'authorization_pending') {
      # keep polling at the same interval
    } elseif ($err -eq 'slow_down') {
      $interval += 5
    } elseif ($err -in 'authorization_declined', 'access_denied') {
      throw "Sign-in was declined ($err)."
    } elseif ($err -eq 'expired_token') {
      throw 'The device code expired (expired_token). Start a new sign-in.'
    } elseif ($err -eq 'bad_verification_code') {
      throw 'The token endpoint did not recognize the device code (bad_verification_code).'
    } else {
      throw "Token endpoint returned HTTP $($r.StatusCode) $err $desc".Trim()
    }
  }
}

#endregion

#region cache -------------------------------------------------------------------------------------

function Get-DefaultStateDir {
  [CmdletBinding()]
  param()
  $base = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $HOME '.local/state' }
  Join-Path $base 'm365-graph-agent-ops'
}

function Get-TokenCachePath {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $TenantId,
    [Parameter(Mandatory)][string] $AuthProfile,
    [string] $StateDir = (Get-DefaultStateDir)
  )
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$($TenantId.ToLowerInvariant())|$AuthProfile"))
  } finally { $sha.Dispose() }
  $hash = (-join ($bytes[0..5] | ForEach-Object { $_.ToString('x2') }))
  Join-Path $StateDir "token-$AuthProfile-$hash.dpapi"
}

function Assert-Dpapi {
  if (-not $IsWindows) {
    throw 'Token caching uses Windows DPAPI and is only supported on Windows. Use -NoCache elsewhere.'
  }
}

function Save-AccessTokenCache {
  <#
  .SYNOPSIS
    Writes the access token DPAPI-encrypted (current user) plus a small metadata file with its not-after time.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $Path,
    [Parameter(Mandatory)][securestring] $AccessToken,
    [int] $ExpiresIn = 3600
  )
  Assert-Dpapi
  $dir = Split-Path -Parent $Path
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  $AccessToken | ConvertFrom-SecureString | Set-Content -LiteralPath $Path -Encoding ascii -NoNewline
  $notAfter = (& $script:AuthClock).AddSeconds([math]::Max($ExpiresIn - 300, 0))
  [pscustomobject]@{ notAfterUtc = $notAfter.ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath "$Path.meta.json" -Encoding utf8
}

function Read-AccessTokenCache {
  <#
  .SYNOPSIS
    Returns the cached access token as a SecureString, or $null if missing, older than MaxAgeMinutes,
    past its not-after time, or not decryptable by this Windows user.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $Path,
    [int] $MaxAgeMinutes = 50
  )
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  $age = (Get-Date) - (Get-Item -LiteralPath $Path).LastWriteTime
  $expired = $age.TotalMinutes -ge $MaxAgeMinutes
  $meta = "$Path.meta.json"
  if (-not $expired -and (Test-Path -LiteralPath $meta)) {
    try {
      $m = Get-Content -LiteralPath $meta -Raw | ConvertFrom-Json
      $na = [datetimeoffset]::Parse([string]$m.notAfterUtc, [System.Globalization.CultureInfo]::InvariantCulture)
      if ((& $script:AuthClock) -ge $na) { $expired = $true }
    } catch { $expired = $true }
  }
  if ($expired) {
    Remove-AccessTokenCache -Path $Path
    return $null
  }
  Assert-Dpapi
  try {
    return (Get-Content -LiteralPath $Path -Raw | ConvertTo-SecureString -ErrorAction Stop)
  } catch {
    return $null
  }
}

function Remove-AccessTokenCache {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string] $Path)
  Remove-Item -LiteralPath $Path, "$Path.meta.json" -Force -ErrorAction SilentlyContinue
}

function Get-AccessTokenCacheNotAfter {
  <#
  .SYNOPSIS
    The time after which the cached token will no longer be served: file age limit or the token's own
    not-after time, whichever is earlier. $null if there is no cache file.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $Path,
    [int] $MaxAgeMinutes = 50
  )
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  $byAge = [datetimeoffset](Get-Item -LiteralPath $Path).LastWriteTime.AddMinutes($MaxAgeMinutes)
  $meta = "$Path.meta.json"
  if (Test-Path -LiteralPath $meta) {
    try {
      $m = Get-Content -LiteralPath $meta -Raw | ConvertFrom-Json
      $na = [datetimeoffset]::Parse([string]$m.notAfterUtc, [System.Globalization.CultureInfo]::InvariantCulture)
      if ($na -lt $byAge) { return $na }
    } catch { return [datetimeoffset]::MinValue }
  }
  $byAge
}

#endregion

#region the one call the tools use ----------------------------------------------------------------

function Get-AgentAccessToken {
  <#
  .SYNOPSIS
    Returns an access token for a named profile: from the DPAPI cache if fresh, otherwise by device code.
  .DESCRIPTION
    With -UserCodeFile, the user code line is written to that file the moment it exists, so a launcher in
    another process can relay it to the human within seconds. -CacheOnly never starts a sign-in; the tools
    use it so that sign-in always happens through auth/Start-DeviceLogin.ps1, where the agent can see the code.
  .OUTPUTS
    AccessToken (SecureString), Source ('cache' or 'device-code'), AuthProfile, GrantedScopes, and NotAfter: the
    time after which this token should not be used. For a cached token that is counted from when the token was
    issued, not from now, so a long-running caller knows how much life is really left.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $TenantId,
    [Parameter(Mandatory)][string] $AuthProfile,
    [string] $StateDir = (Get-DefaultStateDir),
    [int] $MaxCacheAgeMinutes = 50,
    [string] $UserCodeFile,
    [switch] $NoCache,
    [switch] $CacheOnly
  )
  Assert-TenantId -TenantId $TenantId
  $p = Get-AgentAuthProfile -Name $AuthProfile
  $cachePath = Get-TokenCachePath -TenantId $TenantId -AuthProfile $AuthProfile -StateDir $StateDir
  if (-not $NoCache) {
    $cached = Read-AccessTokenCache -Path $cachePath -MaxAgeMinutes $MaxCacheAgeMinutes
    if ($cached) {
      $na = Get-AccessTokenCacheNotAfter -Path $cachePath -MaxAgeMinutes $MaxCacheAgeMinutes
      return [pscustomobject]@{ AccessToken = $cached; Source = 'cache'; AuthProfile = $AuthProfile; GrantedScopes = @(); NotAfter = $na }
    }
  }
  if ($CacheOnly) {
    throw "No fresh cached token for profile '$AuthProfile'. Run: pwsh -File auth/Start-DeviceLogin.ps1 -TenantId $TenantId -AuthProfile $AuthProfile, relay the code, and rerun this after sign-in completes."
  }
  $dc = Request-DeviceCode -TenantId $TenantId -ClientId $p.ClientId -Scope $p.Scopes
  $line = "USER_CODE=$($dc.UserCode) URL=$($dc.VerificationUri) EXPIRES_IN=$($dc.ExpiresIn) PROFILE=$AuthProfile"
  if ($UserCodeFile) {
    $tmp = "$UserCodeFile.tmp"
    Set-Content -LiteralPath $tmp -Value $line -Encoding utf8
    Move-Item -LiteralPath $tmp -Destination $UserCodeFile -Force
  } else {
    # Status goes to the host, never to the pipeline: this function's pipeline output is the token object.
    Write-Host $line
  }
  try {
    $tok = Wait-DeviceCodeToken -TenantId $TenantId -ClientId $p.ClientId -DeviceCodeResponse $dc
  } finally {
    if ($UserCodeFile) { Remove-Item -LiteralPath $UserCodeFile -Force -ErrorAction SilentlyContinue }
  }
  # Default access token lifetimes are 60 to 90 minutes; if the endpoint did not say, assume the shortest.
  $expiresIn = if ($tok.ExpiresIn -gt 0) { $tok.ExpiresIn } else { 3600 }
  if (-not $NoCache) {
    Save-AccessTokenCache -Path $cachePath -AccessToken $tok.AccessToken -ExpiresIn $expiresIn
  }
  $issued = & $script:AuthClock
  $notAfter = $issued.AddMinutes($MaxCacheAgeMinutes)
  $byExpiry = $issued.AddSeconds([math]::Max($expiresIn - 300, 0))
  if ($byExpiry -lt $notAfter) { $notAfter = $byExpiry }
  [pscustomobject]@{ AccessToken = $tok.AccessToken; Source = 'device-code'; AuthProfile = $AuthProfile; GrantedScopes = $tok.GrantedScopes; NotAfter = $notAfter }
}

function Connect-AgentGraph {
  <#
  .SYNOPSIS
    Hands an access token to the Microsoft Graph PowerShell SDK and reads the context back.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][securestring] $AccessToken)
  if (-not (Get-Command -Name Connect-MgGraph -ErrorAction SilentlyContinue)) {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
  }
  Connect-MgGraph -AccessToken $AccessToken -NoWelcome -ErrorAction Stop | Out-Null
  $ctx = Get-MgContext
  if (-not $ctx) { throw 'Connect-MgGraph returned no context after the token hand-off.' }
  $account = $null
  try {
    $me = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=userPrincipalName' -OutputType PSObject -ErrorAction Stop
    $account = $me.userPrincipalName
  } catch {
    $account = '(could not read /me)'
  }
  [pscustomobject]@{ Account = $account; AuthType = $ctx.AuthType; ScopeCount = @($ctx.Scopes).Count }
}

function Connect-AgentExchange {
  <#
  .SYNOPSIS
    Hands an access token to Connect-ExchangeOnline and reads the connection back.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][securestring] $AccessToken,
    [Parameter(Mandatory)][string] $UserPrincipalName
  )
  if (-not (Get-Command -Name Connect-ExchangeOnline -ErrorAction SilentlyContinue)) {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
  }
  $plain = [System.Net.NetworkCredential]::new('', $AccessToken).Password
  try {
    Connect-ExchangeOnline -AccessToken $plain -UserPrincipalName $UserPrincipalName -ShowBanner:$false -ErrorAction Stop
  } finally {
    $plain = $null
  }
  $ci = @(Get-ConnectionInformation | Where-Object { $_.State -eq 'Connected' }) | Select-Object -First 1
  if (-not $ci) { throw 'Connect-ExchangeOnline did not leave a connected session.' }
  [pscustomobject]@{ UserPrincipalName = $ci.UserPrincipalName; TenantId = $ci.TenantID; ConnectionUri = $ci.ConnectionUri }
}

#endregion

Export-ModuleMember -Function @(
  'Set-DeviceAuthTestHook', 'Get-AgentAuthProfile', 'Request-DeviceCode', 'Wait-DeviceCodeToken',
  'Get-DefaultStateDir', 'Get-TokenCachePath', 'Save-AccessTokenCache', 'Read-AccessTokenCache',
  'Remove-AccessTokenCache', 'Get-AccessTokenCacheNotAfter', 'Get-AgentAccessToken', 'Connect-AgentGraph',
  'Connect-AgentExchange'
)
