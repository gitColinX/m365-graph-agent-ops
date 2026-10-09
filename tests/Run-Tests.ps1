#Requires -Version 7.2
<#
.SYNOPSIS
  Offline tests for the auth module, the REST layer and the helpers, against synthetic fixtures only.

.DESCRIPTION
  No tenant, no network. The process sets M365AGENTOPS_OFFLINE=1, so any call that slips past the fake
  transports throws instead of reaching Microsoft. No Pester dependency: a tiny assert helper keeps this
  runnable on a clean machine.

    pwsh -NoProfile -File tests/Run-Tests.ps1

  Exit code is the number of failed tests.
#>
[CmdletBinding()]
param([string] $TempRoot)
$ErrorActionPreference = 'Stop'
$env:M365AGENTOPS_OFFLINE = '1'
$repoRoot = Split-Path -Parent $PSScriptRoot
$fx = Join-Path $PSScriptRoot 'fixtures'
Import-Module (Join-Path $repoRoot 'auth' 'DeviceCodeAuth.psm1') -Force
Import-Module (Join-Path $repoRoot 'lib' 'AgentGraph.psm1') -Force
if (-not $TempRoot) { $TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "m365-graph-agent-ops-tests-$PID" }
New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null

$script:Passed = 0
$script:Failed = [System.Collections.Generic.List[string]]::new()
function Test-Case([string] $Name, [scriptblock] $Body) {
  try {
    & $Body
    $script:Passed++
    Write-Host "PASS $Name"
  } catch {
    $script:Failed.Add($Name)
    Write-Host "FAIL $Name :: $($_.Exception.Message)"
  }
}
function Assert-True($Condition, [string] $Message = 'expected true') { if (-not $Condition) { throw $Message } }
function Assert-Equal($Expected, $Actual, [string] $Message = '') {
  if ($Expected -ne $Actual) { throw "expected '$Expected' but got '$Actual'. $Message" }
}
function Assert-Throws([scriptblock] $Body, [string] $Like) {
  $threw = $false
  try { & $Body } catch {
    $threw = $true
    if ($Like -and $_.Exception.Message -notlike $Like) { throw "threw '$($_.Exception.Message)', expected like '$Like'" }
  }
  if (-not $threw) { throw "expected an exception like '$Like'" }
}
function Get-Fixture([string] $Name) { Get-Content -LiteralPath (Join-Path $fx $Name) -Raw }
function New-Resp([int] $Status, [string] $Content, [hashtable] $Headers = @{}) {
  [pscustomobject]@{ StatusCode = $Status; Headers = $Headers; Content = $Content }
}
function ConvertTo-Plain([securestring] $s) { [System.Net.NetworkCredential]::new('', $s).Password }

# A fake world: queued HTTP responses, a recorded request log, a fake clock that only moves when we "sleep".
function New-FakeWorld {
  $w = @{
    Queue    = [System.Collections.Generic.Queue[object]]::new()
    Requests = [System.Collections.Generic.List[object]]::new()
    Sleeps   = [System.Collections.Generic.List[double]]::new()
    Now      = [datetimeoffset]::Parse('2026-01-01T00:00:00Z')
    OnToken  = $null
  }
  $w.Transport = {
    param($req)
    $w.Requests.Add($req)
    if ($w.OnToken -and $req.Uri -like '*/token') { & $w.OnToken $req }
    if ($w.Queue.Count -eq 0) { throw "fake transport: no response queued for $($req.Method) $($req.Uri)" }
    $w.Queue.Dequeue()
  }.GetNewClosure()
  $w.Sleeper = { param($s) $w.Sleeps.Add([double]$s); $w.Now = $w.Now.AddSeconds([double]$s) }.GetNewClosure()
  $w.Clock = { $w.Now }.GetNewClosure()
  $w
}

$tenant = 'contoso.onmicrosoft.com'
$graphClient = '14d82eec-204b-4c2f-b7e8-296a70dab67e'

#region device authorization grant ---------------------------------------------------------------

Test-Case 'Request-DeviceCode posts the form to the tenant devicecode endpoint' {
  $w = New-FakeWorld
  $w.Queue.Enqueue((New-Resp 200 (Get-Fixture 'devicecode-response.json')))
  Set-DeviceAuthTestHook -Transport $w.Transport -Sleeper $w.Sleeper -Clock $w.Clock
  $dc = Request-DeviceCode -TenantId $tenant -ClientId $graphClient -Scope @('https://graph.microsoft.com/User.Read.All')
  Assert-Equal 'TESTCODE1' $dc.UserCode
  Assert-True ($dc.DeviceCode -is [securestring]) 'device code must be held as a SecureString'
  Assert-Equal 900 $dc.ExpiresIn
  $req = $w.Requests[0]
  Assert-Equal "https://login.microsoftonline.com/$tenant/oauth2/v2.0/devicecode" $req.Uri
  Assert-True ($req.Body -like '*client_id=14d82eec*') 'client id in form body'
  Assert-True ($req.Body -notlike '*offline_access*') 'no offline_access requested'
  Assert-Equal 'application/x-www-form-urlencoded' $req.ContentType
}

Test-Case 'offline_access is refused before any request is sent' {
  $w = New-FakeWorld
  Set-DeviceAuthTestHook -Transport $w.Transport -Sleeper $w.Sleeper -Clock $w.Clock
  Assert-Throws { Request-DeviceCode -TenantId $tenant -ClientId $graphClient -Scope @('https://graph.microsoft.com/User.Read.All', 'offline_access') } '*offline_access is not allowed*'
  Assert-Equal 0 $w.Requests.Count
}

Test-Case 'offline_access inside one space-separated scope string is refused too' {
  $w = New-FakeWorld
  Set-DeviceAuthTestHook -Transport $w.Transport -Sleeper $w.Sleeper -Clock $w.Clock
  Assert-Throws { Request-DeviceCode -TenantId $tenant -ClientId $graphClient -Scope @('offline_access https://graph.microsoft.com/User.Read') } '*offline_access is not allowed*'
  Assert-Throws { Request-DeviceCode -TenantId $tenant -ClientId $graphClient -Scope @("https://graph.microsoft.com/User.Read`toffline_access") } '*offline_access is not allowed*'
  Assert-Equal 0 $w.Requests.Count
}

Test-Case 'common and organizations tenants are refused' {
  Assert-Throws { Request-DeviceCode -TenantId 'common' -ClientId $graphClient -Scope @('x') } '*Name the tenant*'
  Assert-Throws { Request-DeviceCode -TenantId 'organizations' -ClientId $graphClient -Scope @('x') } '*Name the tenant*'
}

Test-Case 'Wait-DeviceCodeToken honors authorization_pending and slow_down (+5 s), drops the refresh token' {
  $w = New-FakeWorld
  $w.Queue.Enqueue((New-Resp 200 (Get-Fixture 'devicecode-response.json')))
  $w.Queue.Enqueue((New-Resp 400 (Get-Fixture 'token-pending.json')))
  $w.Queue.Enqueue((New-Resp 400 (Get-Fixture 'token-slowdown.json')))
  $w.Queue.Enqueue((New-Resp 400 (Get-Fixture 'token-pending.json')))
  $w.Queue.Enqueue((New-Resp 200 (Get-Fixture 'token-success.json')))
  Set-DeviceAuthTestHook -Transport $w.Transport -Sleeper $w.Sleeper -Clock $w.Clock
  $dc = Request-DeviceCode -TenantId $tenant -ClientId $graphClient -Scope @('https://graph.microsoft.com/User.Read.All')
  $t = Wait-DeviceCodeToken -TenantId $tenant -ClientId $graphClient -DeviceCodeResponse $dc
  Assert-Equal '5,5,10,10' ($w.Sleeps -join ',') 'interval 5, then 10 after slow_down'
  Assert-Equal 'synthetic-access-token-for-tests-only' (ConvertTo-Plain $t.AccessToken)
  Assert-True $t.RefreshTokenDiscarded 'refresh token noticed and dropped'
  Assert-True (-not ($t.PSObject.Properties.Name -contains 'RefreshToken')) 'no refresh token property on the result'
  Assert-Equal 12 $t.GrantedScopes.Count
  $tokenReq = $w.Requests[1]
  Assert-True ($tokenReq.Body -like '*grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code*') 'device code grant type'
}

Test-Case 'Wait-DeviceCodeToken stops on authorization_declined' {
  $w = New-FakeWorld
  $w.Queue.Enqueue((New-Resp 200 (Get-Fixture 'devicecode-response.json')))
  $w.Queue.Enqueue((New-Resp 400 (Get-Fixture 'token-declined.json')))
  Set-DeviceAuthTestHook -Transport $w.Transport -Sleeper $w.Sleeper -Clock $w.Clock
  $dc = Request-DeviceCode -TenantId $tenant -ClientId $graphClient -Scope @('x')
  Assert-Throws { Wait-DeviceCodeToken -TenantId $tenant -ClientId $graphClient -DeviceCodeResponse $dc } '*declined*'
}

Test-Case 'Wait-DeviceCodeToken stops on expired_token' {
  $w = New-FakeWorld
  $w.Queue.Enqueue((New-Resp 200 (Get-Fixture 'devicecode-response.json')))
  $w.Queue.Enqueue((New-Resp 400 (Get-Fixture 'token-expired.json')))
  Set-DeviceAuthTestHook -Transport $w.Transport -Sleeper $w.Sleeper -Clock $w.Clock
  $dc = Request-DeviceCode -TenantId $tenant -ClientId $graphClient -Scope @('x')
  Assert-Throws { Wait-DeviceCodeToken -TenantId $tenant -ClientId $graphClient -DeviceCodeResponse $dc } '*expired*'
}

Test-Case 'Wait-DeviceCodeToken gives up at expires_in without another request' {
  $w = New-FakeWorld
  $short = (Get-Fixture 'devicecode-response.json') -replace '"expires_in": 900', '"expires_in": 12'
  $w.Queue.Enqueue((New-Resp 200 $short))
  $w.Queue.Enqueue((New-Resp 400 (Get-Fixture 'token-pending.json')))
  $w.Queue.Enqueue((New-Resp 400 (Get-Fixture 'token-pending.json')))
  Set-DeviceAuthTestHook -Transport $w.Transport -Sleeper $w.Sleeper -Clock $w.Clock
  $dc = Request-DeviceCode -TenantId $tenant -ClientId $graphClient -Scope @('x')
  Assert-Throws { Wait-DeviceCodeToken -TenantId $tenant -ClientId $graphClient -DeviceCodeResponse $dc } '*expired before sign-in*'
  Assert-Equal 3 $w.Requests.Count 'devicecode + 2 polls, then the deadline'
}

#endregion

#region cache and the launcher-facing call ---------------------------------------------------------

if ($IsWindows) {
  Test-Case 'DPAPI cache round-trips and expires by file age' {
    Set-DeviceAuthTestHook
    $dir = Join-Path $TempRoot 'cache1'
    $p = Get-TokenCachePath -TenantId $tenant -AuthProfile 'GraphRead' -StateDir $dir
    $sec = ConvertTo-SecureString 'synthetic-cache-token' -AsPlainText -Force
    Save-AccessTokenCache -Path $p -AccessToken $sec -ExpiresIn 4000
    $raw = Get-Content -LiteralPath $p -Raw
    Assert-True ($raw -notmatch 'synthetic-cache-token') 'cache file must not hold the token in clear text'
    Assert-Equal 'synthetic-cache-token' (ConvertTo-Plain (Read-AccessTokenCache -Path $p))
    (Get-Item -LiteralPath $p).LastWriteTime = (Get-Date).AddMinutes(-51)
    Assert-True ($null -eq (Read-AccessTokenCache -Path $p -MaxAgeMinutes 50)) 'stale cache returns nothing'
    Assert-True (-not (Test-Path -LiteralPath $p)) 'stale cache file removed'
  }

  Test-Case 'cache also expires at the token''s own expires_in' {
    Set-DeviceAuthTestHook
    $dir = Join-Path $TempRoot 'cache2'
    $p = Get-TokenCachePath -TenantId $tenant -AuthProfile 'GraphRead' -StateDir $dir
    Save-AccessTokenCache -Path $p -AccessToken (ConvertTo-SecureString 'x' -AsPlainText -Force) -ExpiresIn 200
    Assert-True ($null -eq (Read-AccessTokenCache -Path $p -MaxAgeMinutes 50)) 'expires_in under 5 minutes leaves no usable cache'
  }

  Test-Case 'Get-AgentAccessToken writes the user code file during polling, deletes it after, caches the token' {
    $w = New-FakeWorld
    $codeFile = Join-Path $TempRoot 'usercode.txt'
    $seen = @{ DuringPoll = $false; Line = '' }
    $w.OnToken = { param($req) if (Test-Path -LiteralPath $codeFile) { $seen.DuringPoll = $true; $seen.Line = (Get-Content -LiteralPath $codeFile -Raw) } }.GetNewClosure()
    $w.Queue.Enqueue((New-Resp 200 (Get-Fixture 'devicecode-response.json')))
    $w.Queue.Enqueue((New-Resp 400 (Get-Fixture 'token-pending.json')))
    $w.Queue.Enqueue((New-Resp 200 (Get-Fixture 'token-success.json')))
    Set-DeviceAuthTestHook -Transport $w.Transport -Sleeper $w.Sleeper -Clock $w.Clock
    $dir = Join-Path $TempRoot 'state3'
    $r = Get-AgentAccessToken -TenantId $tenant -AuthProfile GraphRead -StateDir $dir -UserCodeFile $codeFile
    Assert-Equal 'device-code' $r.Source
    Assert-True $seen.DuringPoll 'user code file existed while polling'
    Assert-True ($seen.Line -like 'USER_CODE=TESTCODE1 URL=https://microsoft.com/devicelogin*') 'user code line format'
    Assert-True ($seen.Line -notlike '*synthetic-device-code*') 'device_code never written'
    Assert-True (-not (Test-Path -LiteralPath $codeFile)) 'user code file removed after sign-in'
    Assert-Equal 50 ([int]($r.NotAfter - $w.Now).TotalMinutes) 'fresh token: usable for the 50-minute cache life (expires_in is longer)'
    # Same fake clock: the cached token's not-after time was computed from it.
    $again = Get-AgentAccessToken -TenantId $tenant -AuthProfile GraphRead -StateDir $dir -CacheOnly
    Assert-Equal 'cache' $again.Source
    Assert-Equal 'synthetic-access-token-for-tests-only' (ConvertTo-Plain $again.AccessToken)
  }

  Test-Case 'a cached token reports how much life it has left, counted from when it was issued' {
    Set-DeviceAuthTestHook
    $dir = Join-Path $TempRoot 'state4'
    $p = Get-TokenCachePath -TenantId $tenant -AuthProfile 'GraphRead' -StateDir $dir
    Save-AccessTokenCache -Path $p -AccessToken (ConvertTo-SecureString 'synthetic-old-token' -AsPlainText -Force) -ExpiresIn 4000
    (Get-Item -LiteralPath $p).LastWriteTime = (Get-Date).AddMinutes(-40)
    $t = Get-AgentAccessToken -TenantId $tenant -AuthProfile GraphRead -StateDir $dir -CacheOnly
    $left = ($t.NotAfter - [datetimeoffset]::Now).TotalMinutes
    Assert-True ($left -gt 9 -and $left -lt 11) "a 40-minute-old token has about 10 minutes left, got $left"
  }
}

Test-Case 'Get-AgentAccessToken -CacheOnly never starts a sign-in' {
  $w = New-FakeWorld
  Set-DeviceAuthTestHook -Transport $w.Transport -Sleeper $w.Sleeper -Clock $w.Clock
  Assert-Throws { Get-AgentAccessToken -TenantId $tenant -AuthProfile IntuneRead -StateDir (Join-Path $TempRoot 'empty') -CacheOnly } '*Start-DeviceLogin.ps1*'
  Assert-Equal 0 $w.Requests.Count
}

Test-Case 'auth profiles: no offline_access anywhere; read profiles request no write scopes' {
  # "Request", not "carry": with the shared client the token can still carry consented write scopes.
  $all = @(Get-AgentAuthProfile)
  Assert-True ($all.Count -ge 9) 'profiles listed'
  foreach ($p in $all) { Assert-True ($p.Scopes -notmatch 'offline_access') "$($p.Name) must not request offline_access" }
  foreach ($p in @($all | Where-Object { -not $_.Write })) { Assert-True ($p.Scopes -notmatch 'ReadWrite|AccessAsUser|FullControl') "$($p.Name) is marked read-only" }
  Assert-Throws { Get-AgentAuthProfile -Name 'NoSuchProfile' } '*Unknown auth profile*'
}

Test-Case 'tool ValidateSets only name profiles that exist' {
  $names = @(Get-AgentAuthProfile | ForEach-Object Name)
  $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'tools' 'Invoke-GraphRead.ps1'), [ref]$null, [ref]$null)
  $param = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'AuthProfile' }
  $vs = $param.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' }
  $vals = @($vs.PositionalArguments | ForEach-Object { $_.Value })
  Assert-True ($vals.Count -gt 0) 'found the ValidateSet'
  foreach ($v in $vals) { Assert-True ($names -contains $v) "profile '$v' missing from DeviceCodeAuth.psm1" }
}

#endregion

#region REST layer ---------------------------------------------------------------------------------

$fakeToken = ConvertTo-SecureString 'synthetic-graph-token' -AsPlainText -Force

Test-Case 'read-only session blocks PATCH before any request is sent' {
  $w = New-FakeWorld
  Set-GraphRestTestHook -Transport $w.Transport -Sleeper $w.Sleeper
  Set-GraphRestContext -AccessToken $fakeToken
  Assert-Throws { Invoke-GraphRest -Method PATCH -Uri 'beta/deviceAppManagement/mobileApps/x' -Body @{ owner = 'x' } } '*read-only*'
  Assert-Equal 0 $w.Requests.Count
}

Test-Case 'the bearer token is never sent off graph.microsoft.com' {
  $w = New-FakeWorld
  Set-GraphRestTestHook -Transport $w.Transport -Sleeper $w.Sleeper
  Set-GraphRestContext -AccessToken $fakeToken
  Assert-Throws { Invoke-GraphRest -Uri 'https://graph.microsoft.com.example.com/v1.0/users' } '*Refusing to send a Graph token*'
  Assert-Throws { Invoke-GraphRest -Uri 'https://example.com/v1.0/users' } '*Refusing*'
  Assert-Throws { Invoke-GraphRest -Uri 'users' } '*must start with v1.0/ or beta/*'
  Assert-Equal 0 $w.Requests.Count
}

Test-Case 'Get-GraphPaged follows every nextLink' {
  $w = New-FakeWorld
  'graph-users-page1.json', 'graph-users-page2.json', 'graph-users-page3.json' | ForEach-Object { $w.Queue.Enqueue((New-Resp 200 (Get-Fixture $_))) }
  Set-GraphRestTestHook -Transport $w.Transport -Sleeper $w.Sleeper
  Set-GraphRestContext -AccessToken $fakeToken
  $items = @(Get-GraphPaged -Uri 'v1.0/users?$select=id,displayName')
  Assert-Equal 5 $items.Count
  Assert-Equal 3 $w.Requests.Count
  Assert-Equal 'Bearer synthetic-graph-token' $w.Requests[0].Headers.Authorization
  Assert-True ($w.Requests[2].Uri -like '*skiptoken=synthetic-page-3') 'third request used the second nextLink'
}

Test-Case 'a nextLink pointing off Graph stops paging' {
  $w = New-FakeWorld
  $evil = (Get-Fixture 'graph-users-page1.json') -replace 'https://graph.microsoft.com/v1.0/users\?\$skiptoken=synthetic-page-2', 'https://attacker.example.net/v1.0/users'
  $w.Queue.Enqueue((New-Resp 200 $evil))
  Set-GraphRestTestHook -Transport $w.Transport -Sleeper $w.Sleeper
  Set-GraphRestContext -AccessToken $fakeToken
  Assert-Throws { @(Get-GraphPaged -Uri 'v1.0/users') } '*Refusing*'
  Assert-Equal 1 $w.Requests.Count
}

Test-Case '429 with Retry-After waits exactly that long, then succeeds' {
  $w = New-FakeWorld
  $w.Queue.Enqueue((New-Resp 429 (Get-Fixture 'graph-429.json') @{ 'Retry-After' = '7' }))
  $w.Queue.Enqueue((New-Resp 200 (Get-Fixture 'graph-users-page3.json')))
  Set-GraphRestTestHook -Transport $w.Transport -Sleeper $w.Sleeper
  Set-GraphRestContext -AccessToken $fakeToken
  $r = Invoke-GraphRest -Uri 'v1.0/users'
  Assert-Equal '7' ($w.Sleeps -join ',')
  Assert-Equal 1 @($r.value).Count
}

Test-Case '503 without Retry-After backs off 2, 4 then succeeds' {
  $w = New-FakeWorld
  $w.Queue.Enqueue((New-Resp 503 ''))
  $w.Queue.Enqueue((New-Resp 503 ''))
  $w.Queue.Enqueue((New-Resp 200 '{"id":"x"}'))
  Set-GraphRestTestHook -Transport $w.Transport -Sleeper $w.Sleeper
  Set-GraphRestContext -AccessToken $fakeToken
  $r = Invoke-GraphRest -Uri 'v1.0/organization'
  Assert-Equal '2,4' ($w.Sleeps -join ',')
  Assert-Equal 'x' $r.id
}

Test-Case 'throttling that never clears surfaces HTTP 429 to the caller' {
  $w = New-FakeWorld
  1..4 | ForEach-Object { $w.Queue.Enqueue((New-Resp 429 (Get-Fixture 'graph-429.json') @{ 'Retry-After' = '1' })) }
  Set-GraphRestTestHook -Transport $w.Transport -Sleeper $w.Sleeper
  Set-GraphRestContext -AccessToken $fakeToken
  $status = 0
  try { Invoke-GraphRest -Uri 'v1.0/users' -MaxRetries 3 } catch { $status = Get-GraphErrorStatus $_ }
  Assert-Equal 429 $status
  Assert-Equal 3 $w.Sleeps.Count
}

Test-Case 'a write that gets 503 is not retried, and the error says to read back first' {
  $w = New-FakeWorld
  $w.Queue.Enqueue((New-Resp 503 ''))
  $w.Queue.Enqueue((New-Resp 201 '{"id":"x"}'))
  Set-GraphRestTestHook -Transport $w.Transport -Sleeper $w.Sleeper
  Set-GraphRestContext -AccessToken $fakeToken -AllowWrites
  $status = 0
  $msg = ''
  try { Invoke-GraphRest -Method POST -Uri 'v1.0/invitations' -Body @{ invitedUserEmailAddress = 'partner.user@example.com' } } catch { $status = Get-GraphErrorStatus $_; $msg = $_.Exception.Message }
  Assert-Equal 503 $status
  Assert-Equal 1 $w.Requests.Count 'one POST only'
  Assert-True ($msg -like '*Read the object back*') $msg
  Set-GraphRestContext -AccessToken $fakeToken
}

Test-Case 'a write that gets 429 is retried after Retry-After' {
  $w = New-FakeWorld
  $w.Queue.Enqueue((New-Resp 429 (Get-Fixture 'graph-429.json') @{ 'Retry-After' = '3' }))
  $w.Queue.Enqueue((New-Resp 201 '{"id":"x"}'))
  Set-GraphRestTestHook -Transport $w.Transport -Sleeper $w.Sleeper
  Set-GraphRestContext -AccessToken $fakeToken -AllowWrites
  $r = Invoke-GraphRest -Method POST -Uri 'v1.0/invitations' -Body @{ invitedUserEmailAddress = 'partner.user@example.com' }
  Assert-Equal 'x' $r.id
  Assert-Equal '3' ($w.Sleeps -join ',')
  Assert-Equal 2 $w.Requests.Count
  Set-GraphRestContext -AccessToken $fakeToken
}

Test-Case 'Retry-After as an HTTP date, and the cap' {
  $future = [datetimeoffset]::UtcNow.AddSeconds(30).ToString('r')
  $s = Get-RetryDelaySeconds -Headers @{ 'Retry-After' = $future }
  Assert-True ($s -ge 28 -and $s -le 31) "got $s"
  Assert-Equal 120 (Get-RetryDelaySeconds -Headers @{ 'retry-after' = '9999' } -MaxSeconds 120)
}

Test-Case 'writes go through once -AllowWrites is set' {
  $w = New-FakeWorld
  $w.Queue.Enqueue((New-Resp 204 ''))
  Set-GraphRestTestHook -Transport $w.Transport -Sleeper $w.Sleeper
  Set-GraphRestContext -AccessToken $fakeToken -AllowWrites
  $null = Invoke-GraphRest -Method PATCH -Uri 'beta/deviceAppManagement/mobileApps/x' -Body ([ordered]@{ '@odata.type' = '#microsoft.graph.win32LobApp'; owner = 'Endpoint team' })
  Assert-Equal 'PATCH' $w.Requests[0].Method
  Assert-Equal 'application/json' $w.Requests[0].ContentType
  Assert-True ($w.Requests[0].Body -like '*"owner":"Endpoint team"*') 'JSON body'
  Set-GraphRestContext -AccessToken $fakeToken
}

#endregion

#region helpers ------------------------------------------------------------------------------------

Test-Case 'appRoleAssignment id decodes to its principal GUID' {
  $g = [guid]'0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d'
  $id = (ConvertTo-AppRoleAssignmentIdPrefix -PrincipalId $g) + 'SyntheticSuffixAbCdEfGhIjKlMn'
  Assert-Equal $g (ConvertFrom-AppRoleAssignmentId -Id $id)
  Assert-True ($null -eq (ConvertFrom-AppRoleAssignmentId -Id 'short')) 'short ids return null'
  Assert-True ($null -eq (ConvertFrom-AppRoleAssignmentId -Id '!!!!!!!!!!!!!!!!!!!!!!!!!!!!')) 'bad base64 returns null'
}

Test-Case 'safe delete refuses a group-conveyed grant and allows a direct user grant' {
  $userId = '00000000-0000-4000-8000-0000000000b1'
  $groupId = '00000000-0000-4000-8000-0000000000b2'
  $groupRow = [pscustomobject]@{ id = (ConvertTo-AppRoleAssignmentIdPrefix $groupId) + 'Suffix0123456789abcdefgh'; principalType = 'Group'; principalId = $groupId; principalDisplayName = 'All Users'; resourceDisplayName = 'Print Portal' }
  $userRow = [pscustomobject]@{ id = (ConvertTo-AppRoleAssignmentIdPrefix $userId) + 'Suffix0123456789abcdefgh'; principalType = 'User'; principalId = $userId; principalDisplayName = 'Test User'; resourceDisplayName = 'Print Portal' }
  $d1 = Test-AppRoleDeleteAllowed -Assignment $groupRow -UserId $userId
  Assert-True (-not $d1.Allowed) 'group grant refused'
  Assert-True ($d1.Reason -like '*every member*') 'reason explains the blast radius'
  $d2 = Test-AppRoleDeleteAllowed -Assignment $userRow -UserId $userId
  Assert-True $d2.Allowed 'direct user grant allowed'
  $other = Test-AppRoleDeleteAllowed -Assignment $userRow -UserId '00000000-0000-4000-8000-0000000000b9'
  Assert-True (-not $other.Allowed) 'grant for a different user refused'
  $mismatch = [pscustomobject]@{ id = (ConvertTo-AppRoleAssignmentIdPrefix $groupId) + 'Suffix0123456789abcdefgh'; principalType = 'User'; principalId = $userId; principalDisplayName = 'Test User' }
  Assert-True (-not (Test-AppRoleDeleteAllowed -Assignment $mismatch -UserId $userId).Allowed) 'id that decodes to another principal refused'
  $garbled = [pscustomobject]@{ id = 'x'; principalType = 'User'; principalId = $userId; principalDisplayName = 'Test User' }
  Assert-True (-not (Test-AppRoleDeleteAllowed -Assignment $garbled -UserId $userId).Allowed) 'undecodable id fails closed'
  Assert-True (Test-AppRoleDeleteAllowed -Assignment $garbled -UserId $userId -SkipIdDecodeCheck).Allowed 'explicit override'
}

Test-Case 'membership check pages past 999 (the bug in my original restore step)' {
  $w = New-FakeWorld
  $target = '00000000-0000-4000-8000-0000000000b1'
  $page1 = @{ value = @(1..999 | ForEach-Object { @{ id = ('10000000-0000-4000-8000-{0:d12}' -f $_) } }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/groups/g/transitiveMembers?$skiptoken=p2' } | ConvertTo-Json -Depth 5
  $page2 = @{ value = @(@{ id = $target }) } | ConvertTo-Json -Depth 5
  $w.Queue.Enqueue((New-Resp 200 $page1))
  $w.Queue.Enqueue((New-Resp 200 $page2))
  Set-GraphRestTestHook -Transport $w.Transport -Sleeper $w.Sleeper
  Set-GraphRestContext -AccessToken $fakeToken
  $firstPageOnly = @(($page1 | ConvertFrom-Json).value)
  Assert-True (-not ($firstPageOnly | Where-Object id -eq $target)) 'one page of 999 says: not a member (wrong)'
  $members = @(Get-GraphPaged -Uri 'v1.0/groups/g/transitiveMembers?$select=id&$top=999')
  Assert-Equal 1000 $members.Count
  Assert-True ([bool]($members | Where-Object id -eq $target)) 'all pages say: member (right)'
}

Test-Case 'Resolve-ExactlyOne: none, one (case-insensitive), ambiguous' {
  $apps = @(
    [pscustomobject]@{ id = 'a1'; displayName = 'Remote Support Agent' },
    [pscustomobject]@{ id = 'a2'; displayName = 'Archive Tool' },
    [pscustomobject]@{ id = 'a3'; displayName = 'Archive Tool' }
  )
  Assert-Equal 'NotFound' (Resolve-ExactlyOne -Items $apps -Property displayName -Value 'Nope').Status
  $one = Resolve-ExactlyOne -Items $apps -Property displayName -Value 'remote support agent'
  Assert-Equal 'Resolved' $one.Status
  Assert-Equal 'a1' $one.Item.id
  $two = Resolve-ExactlyOne -Items $apps -Property displayName -Value 'Archive Tool'
  Assert-Equal 'Ambiguous' $two.Status
  Assert-Equal 'a2,a3' ($two.Ids -join ',')
  Assert-Equal 'NotFound' (Resolve-ExactlyOne -Items @() -Property displayName -Value 'x').Status
}

$dh = Get-Fixture 'device-history-cleanup.json' | ConvertFrom-Json
function New-Evidence([hashtable] $Override = @{}) {
  $e = @{
    Now                        = [datetimeoffset]::Parse($dh.now)
    AuditWindowStart           = [datetimeoffset]::Parse($dh.auditWindowStart)
    ManagedDevices             = @($dh.managedDevices)
    EntraDevices               = @($dh.entraDevices)
    AutopilotIdentities        = @($dh.autopilot)
    CleanupRules               = @($dh.cleanupRules)
    MatchingAdminRemovalEvents = @($dh.adminEvents)
  }
  foreach ($k in $Override.Keys) { $e[$k] = $Override[$k] }
  $e
}

Test-Case 'device verdict: cleanup rule by elimination, with the dangling Autopilot pointer noted' {
  $v = Resolve-DeviceRemovalVerdict -Evidence (New-Evidence)
  Assert-Equal 'CleanupRuleByElimination' $v.Verdict
  Assert-Equal 90 $v.CleanupRuleDays
  Assert-Equal '2026-08-08' $v.EligibleFrom.ToString('yyyy-MM-dd')
  Assert-True (@($v.Notes | Where-Object { $_ -like '*no longer exists*' }).Count -eq 1) 'Autopilot pointer note'
}

Test-Case 'device verdict: an admin delete event wins over the rule' {
  $evt = [pscustomobject]@{ activityDateTime = '2026-08-01T10:00:00Z'; displayName = 'Delete ManagedDevice'; activityType = 'Delete ManagedDevice'; actor = [pscustomobject]@{ userPrincipalName = 'admin@contoso.onmicrosoft.com' } }
  $v = Resolve-DeviceRemovalVerdict -Evidence (New-Evidence @{ MatchingAdminRemovalEvents = @($evt) })
  Assert-Equal 'AdminAction' $v.Verdict
  Assert-True ($v.Summary -like '*admin@contoso.onmicrosoft.com*') 'actor named'
}

Test-Case 'device verdict: still enrolled' {
  $v = Resolve-DeviceRemovalVerdict -Evidence (New-Evidence @{ ManagedDevices = @([pscustomobject]@{ id = 'm1' }) })
  Assert-Equal 'StillEnrolled' $v.Verdict
}

Test-Case 'device verdict: undetermined when the audit window starts after the rule could have fired' {
  $v = Resolve-DeviceRemovalVerdict -Evidence (New-Evidence @{ AuditWindowStart = [datetimeoffset]::Parse('2026-09-01T00:00:00Z') })
  Assert-Equal 'Undetermined' $v.Verdict
  Assert-True ($v.Summary -like '*Widen -Since*') 'tells you what to do'
}

Test-Case 'device verdict: undetermined when the device was not yet eligible' {
  $v = Resolve-DeviceRemovalVerdict -Evidence (New-Evidence @{ Now = [datetimeoffset]::Parse('2026-06-01T00:00:00Z') })
  Assert-Equal 'Undetermined' $v.Verdict
}

Test-Case 'device verdict: undetermined, naming the step, when an evidence query failed' {
  $v = Resolve-DeviceRemovalVerdict -Evidence (New-Evidence @{ FailedSteps = @('auditEvents (HTTP 500)') })
  Assert-Equal 'Undetermined' $v.Verdict
  Assert-True ($v.Summary -like '*auditEvents (HTTP 500)*') $v.Summary
  $still = Resolve-DeviceRemovalVerdict -Evidence (New-Evidence @{ FailedSteps = @('auditEvents (HTTP 500)'); ManagedDevices = @([pscustomobject]@{ id = 'm1' }) })
  Assert-Equal 'StillEnrolled' $still.Verdict 'a record that is still there is positive evidence'
}

Test-Case 'OData literals: quotes doubled, then URL-encoded (#EXT#, &, +)' {
  Assert-Equal 'o%27%27brien' (ConvertTo-ODataLiteral "o'brien") 'doubled, then encoded; Graph decodes it back to two quotes'
  $g = ConvertTo-ODataLiteral 'partner.user_example.com#EXT#@contoso.onmicrosoft.com'
  Assert-Equal 'partner.user_example.com%23EXT%23%40contoso.onmicrosoft.com' $g
  Assert-Equal 'R%26D%2BOps' (ConvertTo-ODataLiteral 'R&D+Ops')
}

Test-Case 'read-back compare: ignores key order and server defaults, catches real differences' {
  $sent = @([ordered]@{ detectionType = 'exists'; fileOrFolderName = 'agent.exe'; path = 'C:\Program Files\Agent'; '@odata.type' = '#microsoft.graph.win32LobAppFileSystemDetection' })
  $back = '[{"@odata.type":"#microsoft.graph.win32LobAppFileSystemDetection","path":"C:\\Program Files\\Agent","fileOrFolderName":"agent.exe","check32BitOn64System":false,"detectionType":"exists","operator":"notConfigured","detectionValue":null}]' | ConvertFrom-Json
  Assert-True ($null -eq (Get-ReadBackMismatch -Desired $sent -Actual $back)) 'server defaults and key order are not a mismatch'
  $one = $back[0]
  Assert-True ($null -eq (Get-ReadBackMismatch -Desired $sent -Actual $one)) 'a one-item array unrolled to its item still matches'
  $wrong = '[{"@odata.type":"#microsoft.graph.win32LobAppFileSystemDetection","path":"C:\\Program Files\\Other","fileOrFolderName":"agent.exe","detectionType":"exists"}]' | ConvertFrom-Json
  Assert-True ((Get-ReadBackMismatch -Desired $sent -Actual $wrong -Path 'detectionRules') -like 'detectionRules`[0`].path:*') 'a changed path is reported with its location'
  Assert-True ($null -ne (Get-ReadBackMismatch -Desired 'Endpoint team' -Actual 'endpoint team')) 'plain strings are case-sensitive'
  Assert-True ($null -eq (Get-ReadBackMismatch -Desired '{0000000A-0000-0000-0000-00000000000B}' -Actual '{0000000a-0000-0000-0000-00000000000b}')) 'GUID case is ignored'
  Assert-True ($null -eq (Get-ReadBackMismatch -Desired '' -Actual $null)) 'empty and null are alike'
  Assert-True ($null -ne (Get-ReadBackMismatch -Desired @(1, 2) -Actual @(1))) 'length differences are caught'
}

Test-Case 'session deadline: the earliest token not-after wins over the session limit' {
  $start = [datetimeoffset]::Parse('2026-01-01T10:00:00Z')
  $d1 = Get-SessionDeadline -Start $start -MaxSessionMinutes 55
  Assert-Equal '10:55' $d1.Deadline.UtcDateTime.ToString('HH:mm')
  $d2 = Get-SessionDeadline -Start $start -MaxSessionMinutes 55 -TokenNotAfter @([datetimeoffset]::Parse('2026-01-01T10:12:00Z'), [datetimeoffset]::Parse('2026-01-01T10:40:00Z'))
  Assert-Equal '10:12' $d2.Deadline.UtcDateTime.ToString('HH:mm') 'a cached token issued 38 minutes earlier ends the session at its not-after'
  Assert-True ($d2.Reason -like '*token*') $d2.Reason
}

Test-Case 'collateral check spots a flipped field and a changed detection rule, ignores identical ones' {
  $before = [pscustomobject]@{ owner = 'A'; allowAvailableUninstall = $true; detectionRules = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.win32LobAppProductCodeDetection'; productCode = '{00000000-0000-0000-0000-000000000000}' }) }
  $after = [pscustomobject]@{ owner = 'A'; allowAvailableUninstall = $false; detectionRules = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.win32LobAppFileSystemDetection'; path = 'C:\Program Files\Agent' }) }
  $d = @(Compare-Snapshot -Before $before -After $after -Property owner, allowAvailableUninstall, detectionRules)
  Assert-Equal 'allowAvailableUninstall,detectionRules' (($d | ForEach-Object Property) -join ',')
}

Test-Case 'queue picks NN-name.ps1 in order and skips done and odd files' {
  $q = Join-Path $TempRoot 'queue'
  New-Item -ItemType Directory -Force -Path $q | Out-Null
  'x' | Set-Content (Join-Path $q '20-remediate.ps1')
  'x' | Set-Content (Join-Path $q '10-discovery.ps1')
  'x' | Set-Content (Join-Path $q 'notes.ps1')
  'x' | Set-Content (Join-Path $q '5-bad-name.ps1')
  Assert-Equal '10-discovery.ps1' (Get-NextQueueStep -QueueDir $q).Name
  'done' | Set-Content (Join-Path $q '10-discovery.ps1.done')
  Assert-Equal '20-remediate.ps1' (Get-NextQueueStep -QueueDir $q).Name
  'done' | Set-Content (Join-Path $q '20-remediate.ps1.done')
  Assert-True ($null -eq (Get-NextQueueStep -QueueDir $q)) 'nothing left'
}

Test-Case 'safe file names' {
  Assert-Equal 'Agent_Self-Heal_v2' (ConvertTo-SafeFileName 'Agent: Self-Heal (v2)')
  Assert-Equal 'unnamed' (ConvertTo-SafeFileName '???')
}

Test-Case 'unified audit log paging: one session id, de-duplicated, stops at ResultCount' {
  $batches = Get-Fixture 'ual-batches.json' | ConvertFrom-Json
  $state = @{ Calls = 0; Sessions = [System.Collections.Generic.List[string]]::new() }
  $block = { param($sid) $state.Sessions.Add($sid); $b = $batches[$state.Calls]; $state.Calls++; $b }.GetNewClosure()
  $r = Invoke-UalPagedSearch -SearchBlock $block
  Assert-Equal 7 $r.Records.Count
  Assert-Equal 7 $r.ResultCount
  Assert-Equal 3 $state.Calls 'stopped once ResultCount was reached'
  Assert-Equal 1 @($state.Sessions | Sort-Object -Unique).Count 'same SessionId on every call'
  $bad = { param($sid) @([pscustomobject]@{ Identity = 'x'; ResultIndex = -1; ResultCount = 0 }) }
  Assert-Throws { Invoke-UalPagedSearch -SearchBlock $bad } '*ResultIndex -1*'
}

#endregion

#region static checks over the scripts ------------------------------------------------------------

Test-Case 'every script that can write gates it behind -Apply (or -AllowWrites)' {
  $files = Get-ChildItem (Join-Path $repoRoot 'tools'), (Join-Path $repoRoot 'recipes') -Filter *.ps1
  foreach ($f in $files) {
    $t = Get-Content -LiteralPath $f.FullName -Raw
    $writes = $t -match "Invoke-GraphRest\s+-Method\s+(POST|PATCH|PUT|DELETE)"
    if ($writes) {
      Assert-True ($t -match 'AllowWrites:\$(Apply|AllowWrites)') "$($f.Name) writes through Invoke-GraphRest without gating -AllowWrites on a switch"
    }
    $sdkWrites = $t -match '\b(New-MgInvitation|New-MgGroup)\b'
    if ($sdkWrites) { Assert-True ($t -match 'if \(-not \$Apply\)') "$($f.Name) calls an SDK write without a dry-run branch" }
  }
}

Test-Case 'no script requests offline_access or embeds a tenant id' {
  $files = Get-ChildItem $repoRoot -Recurse -Include *.ps1, *.psm1 -File | Where-Object { $_.FullName -notlike "*$([IO.Path]::DirectorySeparatorChar)tests$([IO.Path]::DirectorySeparatorChar)*" }
  foreach ($f in $files) {
    $t = Get-Content -LiteralPath $f.FullName -Raw
    Assert-True ($t -notmatch "scope\s*=\s*'[^']*offline_access") "$($f.Name) puts offline_access in a scope string"
    $guids = [regex]::Matches($t, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') | ForEach-Object Value | Sort-Object -Unique
    $known = @('14d82eec-204b-4c2f-b7e8-296a70dab67e', 'fb78d390-0c51-40cd-8e17-fdbfab77341b', '00000003-0000-0000-c000-000000000000', '00000002-0000-0ff1-ce00-000000000000', '00000000-0000-0000-0000-000000000000')
    foreach ($g in $guids) { Assert-True ($known -contains $g.ToLowerInvariant()) "$($f.Name) contains an unexpected GUID $g" }
  }
}

Test-Case 'the agent app script only accepts read-only permission names' {
  $t = Get-Content -LiteralPath (Join-Path $repoRoot 'tools' 'New-AgentReadOnlyApp.ps1') -Raw
  $m = [regex]::Match($t, "\`$readOnly = '([^']+)'")
  Assert-True $m.Success 'found the read-only pattern'
  $re = $m.Groups[1].Value
  foreach ($ok in 'User.Read.All', 'RoleManagement.Read.Directory', 'Team.ReadBasic.All', 'DeviceManagementManagedDevices.Read.All') { Assert-True ($ok -match $re) "$ok should pass" }
  foreach ($bad in 'User.ReadWrite.All', 'Directory.AccessAsUser.All', 'Sites.FullControl.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All', 'Application.ReadWrite.OwnedBy') { Assert-True ($bad -notmatch $re) "$bad should be refused" }
}

Test-Case 'the agent app keeps content-reading permissions out of its default app-only set' {
  $path = Join-Path $repoRoot 'tools' 'New-AgentReadOnlyApp.ps1'
  $t = Get-Content -LiteralPath $path -Raw
  $m = [regex]::Match($t, "\`$sensitiveAppOnly = '([^']+)'")
  Assert-True $m.Success 'found the sensitive-permission pattern'
  $re = $m.Groups[1].Value
  foreach ($s in 'Mail.Read', 'Files.Read.All', 'Sites.Read.All', 'UserAuthenticationMethod.Read.All', 'BitlockerKey.Read.All', 'DeviceLocalCredential.Read.All') { Assert-True ($s -match $re) "$s should count as sensitive" }
  foreach ($ok in 'User.Read.All', 'AuditLog.Read.All', 'DeviceManagementManagedDevices.Read.All') { Assert-True ($ok -notmatch $re) "$ok should not count as sensitive" }
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
  $param = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ApplicationPermissions' }
  $defaults = @($param.DefaultValue.SafeGetValue())
  Assert-True ($defaults.Count -ge 10) "found the default application set ($($defaults.Count))"
  foreach ($d in $defaults) { Assert-True ($d -notmatch $re) "default application permission $d reads content or secrets" }
  Assert-Throws { & $path -TenantId $tenant -ApplicationPermissions 'User.Read.All', 'Mail.Read' } '*Refusing application*Mail.Read*'
}

#endregion

#region end to end, offline: the tools refuse to run without a cached token, and the launcher plumbing works

if ($IsWindows) {
  $pwshPath = (Get-Process -Id $PID).Path
  Test-Case 'Invoke-GraphRead.ps1 with no cached token stops and points at the launcher' {
    $fakeLocal = Join-Path $TempRoot 'localappdata1'
    New-Item -ItemType Directory -Force -Path $fakeLocal | Out-Null
    $out = & $pwshPath -NoProfile -NonInteractive -Command "`$env:LOCALAPPDATA='$fakeLocal'; `$env:M365AGENTOPS_OFFLINE='1'; & '$(Join-Path $repoRoot 'tools' 'Invoke-GraphRead.ps1')' -TenantId contoso.onmicrosoft.com -Uri 'v1.0/organization' -OutDir '$(Join-Path $TempRoot 'gr-out')'" 2>&1 | Out-String
    Assert-True ($LASTEXITCODE -ne 0) 'non-zero exit'
    Assert-True ($out -like '*Start-DeviceLogin.ps1*') "message points at the launcher: $out"
  }

  Test-Case 'Start-DeviceLogin.ps1 runs the detached child and reports its failure (network calls blocked)' {
    $state = Join-Path $TempRoot 'launcher-state'
    $out = & $pwshPath -NoProfile -NonInteractive -Command "`$env:M365AGENTOPS_OFFLINE='1'; & '$(Join-Path $repoRoot 'auth' 'Start-DeviceLogin.ps1')' -TenantId contoso.onmicrosoft.com -AuthProfile GraphRead -StateDir '$state' -WaitSeconds 30" 2>&1 | Out-String
    Assert-True ($LASTEXITCODE -eq 1) "exit 1, got $LASTEXITCODE"
    Assert-True ($out -like '*exited before a code was issued*') "launcher noticed the child exit: $out"
    Assert-True ($out -like '*FAIL*Network calls are disabled*') "child status file relayed: $out"
  }
}

#endregion

#region end to end, in-process: each tool against a fake Graph that routes by method and URL ---------

function New-Router([object[]] $Routes) {
  $state = @{ Routes = $Routes; Log = [System.Collections.Generic.List[object]]::new() }
  $state.Transport = {
    param($req)
    $state.Log.Add($req)
    foreach ($r in $state.Routes) {
      if ($req.Method -eq $r.Method -and $req.Uri -match $r.Pattern) {
        $body = if ($r.Body -is [scriptblock]) { & $r.Body $req } else { $r.Body }
        $status = if ($r.ContainsKey('Status')) { $r.Status } else { 200 }
        $content = if ($null -eq $body) { '' } elseif ($body -is [string]) { $body } else { $body | ConvertTo-Json -Depth 20 }
        return [pscustomobject]@{ StatusCode = $status; Headers = @{}; Content = $content }
      }
    }
    throw "router: no route for $($req.Method) $($req.Uri)"
  }.GetNewClosure()
  $state
}
function Invoke-Tool([string] $RelPath, [hashtable] $Params) {
  $global:LASTEXITCODE = 0
  $out = & (Join-Path $repoRoot $RelPath) @Params 2>&1 | Out-String -Width 400
  [pscustomobject]@{ Out = $out; Exit = $global:LASTEXITCODE }
}
$err403 = '{"error":{"code":"Forbidden","message":"Synthetic: not allowed for this role."}}'

if ($IsWindows) {
  $savedLocal = $env:LOCALAPPDATA
  $env:LOCALAPPDATA = Join-Path $TempRoot 'e2e-localappdata'
  New-Item -ItemType Directory -Force -Path $env:LOCALAPPDATA | Out-Null
  Set-DeviceAuthTestHook
  foreach ($p in 'GraphRead', 'IntuneRead', 'IntuneAppWrite', 'AppRoleWrite', 'Onboarding') {
    Save-AccessTokenCache -Path (Get-TokenCachePath -TenantId $tenant -AuthProfile $p) -AccessToken (ConvertTo-SecureString "synthetic-$p" -AsPlainText -Force) -ExpiresIn 3600
  }

  Test-Case 'e2e Invoke-GraphRead.ps1: pages, writes one file per query, records a 403 and exits 3' {
    $rt = New-Router @(
      @{ Method = 'GET'; Pattern = 'skiptoken=synthetic-page-2'; Body = (Get-Fixture 'graph-users-page2.json') },
      @{ Method = 'GET'; Pattern = 'skiptoken=synthetic-page-3'; Body = (Get-Fixture 'graph-users-page3.json') },
      @{ Method = 'GET'; Pattern = 'v1\.0/users\?\$select=id'; Body = (Get-Fixture 'graph-users-page1.json') },
      @{ Method = 'GET'; Pattern = 'auditLogs/signIns'; Status = 403; Body = $err403 }
    )
    Set-GraphRestTestHook -Transport $rt.Transport
    $od = Join-Path $TempRoot 'e2e-graphread'
    $r = Invoke-Tool 'tools/Invoke-GraphRead.ps1' @{ TenantId = $tenant; Uri = @('v1.0/users?$select=id', 'v1.0/auditLogs/signIns'); OutDir = $od }
    Assert-Equal 3 $r.Exit $r.Out
    Assert-True ($r.Out -match 'q01 OK 5 rows') $r.Out
    Assert-True ($r.Out -match 'q02 ERR 403') $r.Out
    Assert-Equal 5 (Get-Content (Join-Path $od 'q01.json') -Raw | ConvertFrom-Json).count
    Assert-Equal 'Bearer synthetic-GraphRead' $rt.Log[0].Headers.Authorization 'used the GraphRead cache'
    Assert-Equal 0 @($rt.Log | Where-Object Method -ne 'GET').Count 'GET only'
  }

  $entraId = '00000000-0000-4000-8000-0000000000d1'
  $historyRoutes = @(
    @{ Method = 'GET'; Pattern = 'deviceManagement/managedDevices\?'; Body = @{ value = @() } },
    @{ Method = 'GET'; Pattern = "beta/devices/$entraId/registeredOwners"; Body = @{ value = @(@{ id = 'u1'; userPrincipalName = 'test.user@contoso.onmicrosoft.com' }) } },
    @{ Method = 'GET'; Pattern = 'beta/devices\?\$filter=displayName'; Body = @{ value = @($dh.entraDevices) } },
    @{ Method = 'GET'; Pattern = 'windowsAutopilotDeviceIdentities'; Body = @{ value = @($dh.autopilot) } },
    @{ Method = 'GET'; Pattern = 'managedDeviceCleanupRules'; Body = @{ value = @($dh.cleanupRules) } },
    @{ Method = 'GET'; Pattern = 'managedDeviceCleanupSettings'; Status = 403; Body = $err403 },
    @{ Method = 'GET'; Pattern = 'deviceManagement/auditEvents'; Body = @{ value = @(
          @{ id = 'e1'; activityDateTime = '2026-07-01T10:00:00Z'; displayName = 'Delete ManagedDevice'; activityType = 'Delete ManagedDevice'; actor = @{ userPrincipalName = 'admin@contoso.onmicrosoft.com' }; resources = @(@{ displayName = 'LT-OTHER9'; resourceId = 'x' }) },
          @{ id = 'e2'; activityDateTime = '2026-07-02T10:00:00Z'; displayName = 'Patch DeviceConfiguration'; activityType = 'Patch DeviceConfiguration'; actor = @{ userPrincipalName = 'admin@contoso.onmicrosoft.com' }; resources = @() }
        ) } },
    @{ Method = 'GET'; Pattern = 'auditLogs/directoryAudits'; Body = @{ value = @() } }
  )
  $historyParams = @{ TenantId = $tenant; SerialNumber = @('SN0001'); DeviceName = @('LT-SN0001'); Since = [datetime]'2025-09-18' }

  Test-Case 'e2e Get-IntuneDeviceHistory.ps1: concludes cleanup rule by elimination, records the 403' {
    $rt = New-Router $historyRoutes
    Set-GraphRestTestHook -Transport $rt.Transport
    $od = Join-Path $TempRoot 'e2e-history'
    $r = Invoke-Tool 'tools/Get-IntuneDeviceHistory.ps1' ($historyParams + @{ OutDir = $od })
    Assert-True ($r.Out -match 'VERDICT=CleanupRuleByElimination') $r.Out
    $md = Get-Content (Join-Path $od 'summary.md') -Raw
    Assert-True ($md -match 'cleanupSettings: HTTP 403') 'the 403 is recorded, not fatal'
    Assert-True ($md -match '\| \.\.\. matching this device \| 0 \|') 'the unrelated delete event did not match'
    $json = Get-ChildItem $od -Filter 'intune-history-*.json' | Select-Object -First 1 | Get-Content -Raw | ConvertFrom-Json
    Assert-Equal 'test.user@contoso.onmicrosoft.com' @($json.entraDeviceOwners)[0].owners[0]
  }

  Test-Case 'e2e Get-IntuneDeviceHistory.ps1: audit events that fail (HTTP 500) give Undetermined, not the cleanup rule' {
    $rt = New-Router (@(@{ Method = 'GET'; Pattern = 'deviceManagement/auditEvents'; Status = 500; Body = '{"error":{"code":"InternalServerError","message":"Synthetic."}}' }) + $historyRoutes)
    Set-GraphRestTestHook -Transport $rt.Transport
    $r = Invoke-Tool 'tools/Get-IntuneDeviceHistory.ps1' ($historyParams + @{ OutDir = (Join-Path $TempRoot 'e2e-history-500') })
    Assert-True ($r.Out -match 'VERDICT=Undetermined') $r.Out
    Assert-True ($r.Out -match 'auditEvents \(HTTP 500\)') $r.Out
  }

  Test-Case 'e2e Get-IntuneDeviceHistory.ps1: managed devices not visible (403) give Undetermined' {
    $rt = New-Router (@(@{ Method = 'GET'; Pattern = 'deviceManagement/managedDevices\?'; Status = 403; Body = $err403 }) + $historyRoutes)
    Set-GraphRestTestHook -Transport $rt.Transport
    $r = Invoke-Tool 'tools/Get-IntuneDeviceHistory.ps1' ($historyParams + @{ OutDir = (Join-Path $TempRoot 'e2e-history-403') })
    Assert-True ($r.Out -match 'VERDICT=Undetermined') $r.Out
    Assert-True ($r.Out -match 'managedDevices\.serial \(HTTP 403\)') $r.Out
  }

  # The fake app server behaves the way Intune did on a real detection rule PATCH (tests/fixtures/win32-app-detection.json):
  # it adds server defaults to the stored detection rule and rewrites the 'detection' entries in 'rules'.
  function New-AppWorld {
    $fxApp = Get-Fixture 'win32-app-detection.json' | ConvertFrom-Json -AsHashtable
    $appId = $fxApp.app.id
    $world = @{
      App              = $fxApp.app
      Defaults         = $fxApp.serverDefaults
      Assignments      = @(@{ id = 'as1'; intent = 'required'; target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } })
      RejectNotes      = $false
      Collateral       = $false
      BreakRequirement = $false
    }
    $routes = @(
      @{ Method = 'GET'; Pattern = 'mobileApps\?\$top=100'; Body = { param($q) @{ value = @($world.App, @{ id = 'a2'; displayName = 'Archive Tool' }, @{ id = 'a3'; displayName = 'Archive Tool' }) } }.GetNewClosure() },
      @{ Method = 'GET'; Pattern = "mobileApps/$appId/assignments"; Body = { param($q) @{ value = @($world.Assignments) } }.GetNewClosure() },
      @{ Method = 'GET'; Pattern = "mobileApps/$appId$"; Body = { param($q) $world.App }.GetNewClosure() },
      @{ Method = 'PATCH'; Pattern = "mobileApps/$appId$"; Body = { param($q)
          $b = $q.Body | ConvertFrom-Json -AsHashtable
          if ($world.RejectNotes -and $b.ContainsKey('notes')) { throw 'reject' }
          foreach ($k in $b.Keys) {
            if ($k -eq '@odata.type') { continue }
            if ($k -ne 'detectionRules') { $world.App[$k] = $b[$k]; continue }
            $stored = @(foreach ($r in @($b[$k])) {
                $copy = [ordered]@{}
                foreach ($rk in $r.Keys) { $copy[$rk] = $r[$rk] }
                $d = $world.Defaults[[string]$r['@odata.type']]
                if ($d) { foreach ($dk in $d.Keys) { if (-not $copy.Contains($dk)) { $copy[$dk] = $d[$dk] } } }
                $copy
              })
            $mirror = @(foreach ($r in $stored) {
                if ($r['@odata.type'] -eq '#microsoft.graph.win32LobAppFileSystemDetection') {
                  [ordered]@{ '@odata.type' = '#microsoft.graph.win32LobAppFileSystemRule'; ruleType = 'detection'; path = $r['path']; fileOrFolderName = $r['fileOrFolderName']
                    check32BitOn64System = $r['check32BitOn64System']; operationType = $r['detectionType']; operator = $r['operator']; comparisonValue = '' }
                }
              })
            $world.App['detectionRules'] = $stored
            $world.App['rules'] = @($mirror) + @($world.App['rules'] | Where-Object { $_['ruleType'] -ne 'detection' })
          }
          if ($world.Collateral) { $world.App['allowAvailableUninstall'] = $false }
          if ($world.BreakRequirement) { foreach ($r in @($world.App['rules'] | Where-Object { $_['ruleType'] -eq 'requirement' })) { $r['valueName'] = 'ChangedBySomethingElse' } }
          $null }.GetNewClosure() }
    )
    $world.Router = New-Router $routes
    # A rejected field becomes a 400 response instead of a thrown error.
    $inner = $world.Router.Transport
    $world.Transport = { param($req) try { & $inner $req } catch { if ($_.Exception.Message -eq 'reject') { [pscustomobject]@{ StatusCode = 400; Headers = @{}; Content = '{"error":{"code":"BadRequest","message":"Synthetic rejection."}}' } } else { throw } } }.GetNewClosure()
    $world
  }

  Test-Case 'e2e Set-IntuneWin32AppField.ps1: dry run sends no PATCH; ambiguous names stop with exit 2' {
    $w = New-AppWorld
    Set-GraphRestTestHook -Transport $w.Transport
    $r = Invoke-Tool 'tools/Set-IntuneWin32AppField.ps1' @{ TenantId = $tenant; AppName = 'remote support agent'; Field = 'owner'; Value = 'Endpoint team'; OutDir = (Join-Path $TempRoot 'e2e-app1') }
    Assert-Equal 0 $r.Exit $r.Out
    Assert-True ($r.Out -match 'DRY RUN') $r.Out
    Assert-Equal 0 @($w.Router.Log | Where-Object Method -ne 'GET').Count 'no writes in a dry run'
    Assert-True (Test-Path (Join-Path $TempRoot 'e2e-app1' 'before.json')) 'rollback snapshot written'
    $r2 = Invoke-Tool 'tools/Set-IntuneWin32AppField.ps1' @{ TenantId = $tenant; AppName = 'Archive Tool'; Field = 'owner'; Value = 'x'; OutDir = (Join-Path $TempRoot 'e2e-app2') }
    Assert-Equal 2 $r2.Exit $r2.Out
    Assert-True ($r2.Out -match 'RESOLVE Ambiguous') $r2.Out
  }

  Test-Case 'e2e Set-IntuneWin32AppField.ps1 -Apply: one PATCH per field, a rejected field does not sink the rest' {
    $w = New-AppWorld
    $w.RejectNotes = $true
    Set-GraphRestTestHook -Transport $w.Transport
    $cj = Join-Path $TempRoot 'changes.json'
    @{ owner = 'Endpoint team'; notes = ('x' * 50); detectionRules = @(@{ '@odata.type' = '#microsoft.graph.win32LobAppFileSystemDetection'; path = 'C:\Program Files\Agent'; fileOrFolderName = 'agent.exe'; detectionType = 'exists' }) } | ConvertTo-Json -Depth 5 | Set-Content $cj
    $r = Invoke-Tool 'tools/Set-IntuneWin32AppField.ps1' @{ TenantId = $tenant; AppName = 'Remote Support Agent'; ChangesJson = $cj; Apply = $true; OutDir = (Join-Path $TempRoot 'e2e-app3') }
    Assert-Equal 4 $r.Exit $r.Out
    Assert-Equal 3 @($w.Router.Log | Where-Object Method -eq 'PATCH').Count 'three fields, three PATCHes'
    Assert-True ($r.Out -match 'PATCH owner\s+OK verified') $r.Out
    Assert-True ($r.Out -match 'PATCH detectionRules\s+OK verified') $r.Out
    Assert-True ($r.Out -match 'PATCH notes\s+ERROR HTTP 400') $r.Out
    Assert-True ($r.Out -match 'COLLATERAL assignments unchanged: True') $r.Out
  }

  Test-Case 'e2e Set-IntuneWin32AppField.ps1 -Apply: collateral change is caught (exit 5)' {
    $w = New-AppWorld
    $w.Collateral = $true
    Set-GraphRestTestHook -Transport $w.Transport
    $r = Invoke-Tool 'tools/Set-IntuneWin32AppField.ps1' @{ TenantId = $tenant; AppName = 'Remote Support Agent'; Field = 'owner'; Value = 'Endpoint team'; Apply = $true; OutDir = (Join-Path $TempRoot 'e2e-app4') }
    Assert-Equal 5 $r.Exit $r.Out
    Assert-True ($r.Out -match 'allowAvailableUninstall: true -> false') $r.Out
  }

  Test-Case 'e2e Set-IntuneWin32AppField.ps1 -Apply: a detection rule change verifies against the server-shaped read-back' {
    $w = New-AppWorld
    Set-GraphRestTestHook -Transport $w.Transport
    $cj = Join-Path $TempRoot 'changes-detection.json'
    '{ "detectionRules": [ { "detectionType": "exists", "fileOrFolderName": "agent.exe", "path": "C:\\Program Files\\Agent", "@odata.type": "#microsoft.graph.win32LobAppFileSystemDetection" } ] }' | Set-Content $cj
    $r = Invoke-Tool 'tools/Set-IntuneWin32AppField.ps1' @{ TenantId = $tenant; AppName = 'Remote Support Agent'; ChangesJson = $cj; Apply = $true; OutDir = (Join-Path $TempRoot 'e2e-app5') }
    Assert-Equal 'notConfigured' $w.App['detectionRules'][0]['operator'] 'the fake added a server default'
    Assert-Equal '#microsoft.graph.win32LobAppFileSystemRule' @($w.App['rules'] | Where-Object { $_['ruleType'] -eq 'detection' })[0]['@odata.type'] 'the fake rewrote the rules mirror'
    Assert-Equal 0 $r.Exit $r.Out
    Assert-True ($r.Out -match 'PATCH detectionRules\s+OK verified') $r.Out
    Assert-True ($r.Out -match 'COLLATERAL fields changed that were not requested: 0') $r.Out
    $w2 = New-AppWorld
    $w2.BreakRequirement = $true
    Set-GraphRestTestHook -Transport $w2.Transport
    $r2 = Invoke-Tool 'tools/Set-IntuneWin32AppField.ps1' @{ TenantId = $tenant; AppName = 'Remote Support Agent'; ChangesJson = $cj; Apply = $true; OutDir = (Join-Path $TempRoot 'e2e-app6') }
    Assert-Equal 5 $r2.Exit $r2.Out
    Assert-True ($r2.Out -match 'rules \(entries other than detection\)') 'a requirement rule that moved is still collateral'
  }

  Test-Case 'e2e Set-IntuneWin32AppField.ps1: command-line changes print in full and need -AllowCommandLineChange' {
    $newCmd = 'msiexec /i "agent.msi" /qn /norestart /L*v "C:\Windows\Temp\agent-install-verbose-log-for-real-failures.log"'
    $w = New-AppWorld
    Set-GraphRestTestHook -Transport $w.Transport
    $r = Invoke-Tool 'tools/Set-IntuneWin32AppField.ps1' @{ TenantId = $tenant; AppName = 'Remote Support Agent'; Field = 'installCommandLine'; Value = $newCmd; Apply = $true; OutDir = (Join-Path $TempRoot 'e2e-app7') }
    Assert-Equal 6 $r.Exit $r.Out
    Assert-Equal 0 @($w.Router.Log | Where-Object Method -eq 'PATCH').Count 'no PATCH without the second switch'
    Assert-True ($r.Out.Contains("FULL NEW:     $newCmd")) "full command printed: $($r.Out)"
    $r2 = Invoke-Tool 'tools/Set-IntuneWin32AppField.ps1' @{ TenantId = $tenant; AppName = 'Remote Support Agent'; Field = 'installCommandLine'; Value = $newCmd; Apply = $true; AllowCommandLineChange = $true; OutDir = (Join-Path $TempRoot 'e2e-app8') }
    Assert-Equal 0 $r2.Exit $r2.Out
    Assert-True ($r2.Out -match 'PATCH installCommandLine\s+OK verified') $r2.Out
  }

  $uId = '00000000-0000-4000-8000-0000000000b1'
  $gId = '00000000-0000-4000-8000-0000000000b2'
  $rId = '00000000-0000-4000-8000-0000000000c9'
  $groupRow = @{ id = (ConvertTo-AppRoleAssignmentIdPrefix $gId) + 'Suffix0123456789abcdefgh'; principalType = 'Group'; principalId = $gId; principalDisplayName = 'All Users'; resourceId = $rId; resourceDisplayName = 'Print Portal'; appRoleId = '00000000-0000-0000-0000-000000000000' }
  $userRow = @{ id = (ConvertTo-AppRoleAssignmentIdPrefix $uId) + 'Suffix0123456789abcdefgh'; principalType = 'User'; principalId = $uId; principalDisplayName = 'Test User'; resourceId = $rId; resourceDisplayName = 'Print Portal'; appRoleId = '00000000-0000-0000-0000-000000000000' }

  Test-Case 'e2e Remove-UserAppRoleAssignment.ps1 -Apply refuses a group grant, counts every member, sends no DELETE' {
    $p1 = @{ value = @(1..999 | ForEach-Object { @{ id = ('10000000-0000-4000-8000-{0:d12}' -f $_) } }); '@odata.nextLink' = "https://graph.microsoft.com/v1.0/groups/$gId/transitiveMembers?`$skiptoken=p2" }
    $rt = New-Router @(
      @{ Method = 'GET'; Pattern = 'v1\.0/users\?\$filter=userPrincipalName'; Body = @{ value = @(@{ id = $uId; userPrincipalName = 'test.user@contoso.onmicrosoft.com'; displayName = 'Test User' }) } },
      @{ Method = 'GET'; Pattern = "users/$uId/appRoleAssignments"; Body = @{ value = @($groupRow) } },
      @{ Method = 'GET'; Pattern = 'skiptoken=p2'; Body = @{ value = @(@{ id = $uId }) } },
      @{ Method = 'GET'; Pattern = "groups/$gId/transitiveMembers"; Body = $p1 }
    )
    Set-GraphRestTestHook -Transport $rt.Transport
    $guestUpn = 'partner.user_example.com#EXT#@contoso.onmicrosoft.com'
    $r = Invoke-Tool 'tools/Remove-UserAppRoleAssignment.ps1' @{ TenantId = $tenant; User = $guestUpn; ResourceDisplayName = 'Print Portal'; Apply = $true; OutDir = (Join-Path $TempRoot 'e2e-ar1') }
    Assert-Equal 3 $r.Exit $r.Out
    Assert-True ($r.Out -match 'reaches 1000 members \(all pages\)\. Target user is a member: True') $r.Out
    Assert-Equal 0 @($rt.Log | Where-Object Method -eq 'DELETE').Count 'no DELETE sent'
    Assert-True ($rt.Log[0].Uri -notmatch '#' -and $rt.Log[0].Uri -match '%23EXT%23') "guest UPN encoded in the filter: $($rt.Log[0].Uri)"
  }

  Test-Case 'e2e Remove-UserAppRoleAssignment.ps1 -Apply deletes a direct grant through the user path and proves only it went' {
    $st = @{ UserRows = @($userRow); ResourceRows = @($userRow, $groupRow) }
    $rt = New-Router @(
      @{ Method = 'GET'; Pattern = "v1\.0/users/$uId\?"; Body = @{ id = $uId; userPrincipalName = 'test.user@contoso.onmicrosoft.com'; displayName = 'Test User' } },
      @{ Method = 'GET'; Pattern = "users/$uId/appRoleAssignments"; Body = { param($q) @{ value = @($st.UserRows) } }.GetNewClosure() },
      @{ Method = 'GET'; Pattern = "servicePrincipals/$rId/appRoleAssignedTo"; Body = { param($q) @{ value = @($st.ResourceRows) } }.GetNewClosure() },
      @{ Method = 'DELETE'; Pattern = "users/$uId/appRoleAssignments/"; Status = 204; Body = { param($q) $st.UserRows = @(); $st.ResourceRows = @($groupRow); $null }.GetNewClosure() }
    )
    Set-GraphRestTestHook -Transport $rt.Transport
    $od = Join-Path $TempRoot 'e2e-ar2'
    $r = Invoke-Tool 'tools/Remove-UserAppRoleAssignment.ps1' @{ TenantId = $tenant; User = $uId; ResourceDisplayName = 'Print Portal'; Apply = $true; OutDir = $od }
    Assert-Equal 0 $r.Exit $r.Out
    $del = @($rt.Log | Where-Object Method -eq 'DELETE')
    Assert-Equal 1 $del.Count
    Assert-True ($del[0].Uri -like "*/v1.0/users/$uId/appRoleAssignments/*") 'deleted through the user path'
    Assert-True ($r.Out -match 'only the target removed: True') $r.Out
    $snap = Get-Content (Join-Path $od 'deleted-assignments.jsonl') -Raw | ConvertFrom-Json
    Assert-Equal $uId $snap.restoreBody.principalId 'snapshot holds the restore call'
  }

  Test-Case 'e2e Export-RemediationRunStates.ps1: one CSV per package with run data' {
    $rt = New-Router @(
      @{ Method = 'GET'; Pattern = 'deviceHealthScripts/s1/deviceRunStates'; Body = @{ value = @(
            @{ detectionState = 'fail'; remediationState = 'success'; lastStateUpdateDateTime = '2026-08-24T10:00:00Z'; preRemediationDetectionScriptOutput = 'NEEDS FIX'; managedDevice = @{ deviceName = 'LT-0001'; userPrincipalName = 'test.user@contoso.onmicrosoft.com' } },
            @{ detectionState = 'success'; remediationState = 'skipped'; lastStateUpdateDateTime = '2026-08-24T11:00:00Z'; preRemediationDetectionScriptOutput = 'HEALTHY'; managedDevice = @{ deviceName = 'LT-0002'; userPrincipalName = 'test.user2@contoso.onmicrosoft.com' } }) } },
      @{ Method = 'GET'; Pattern = 'deviceHealthScripts/s2/deviceRunStates'; Body = @{ value = @() } },
      @{ Method = 'GET'; Pattern = 'deviceHealthScripts\?'; Body = @{ value = @(@{ id = 's1'; displayName = 'Agent: Self-Heal (v2)' }, @{ id = 's2'; displayName = 'Unused package' }) } }
    )
    Set-GraphRestTestHook -Transport $rt.Transport
    $od = Join-Path $TempRoot 'e2e-rem'
    $r = Invoke-Tool 'tools/Export-RemediationRunStates.ps1' @{ TenantId = $tenant; OutDir = $od }
    $csv = @(Get-ChildItem $od -Filter 'RemediationExport_*.csv')
    Assert-Equal 1 $csv.Count $r.Out
    Assert-True ($csv[0].Name -like 'RemediationExport_Agent_Self-Heal_v2_*.csv') $csv[0].Name
    $rows = @(Import-Csv $csv[0].FullName)
    Assert-Equal 2 $rows.Count
    Assert-Equal 'NEEDS FIX' $rows[0].DetectionOutput
    Assert-True ($r.Out -match 'Unused package: no run data, skipped') $r.Out
  }

  Test-Case 'e2e New-AgentReadOnlyApp.ps1: dry run plans delegated + application entries; write and sensitive app-only permissions refused' {
    $graphSpBody = @{ value = @(@{ id = 'sp-graph'; appId = '00000003-0000-0000-c000-000000000000'; displayName = 'Microsoft Graph'
          oauth2PermissionScopes = @(@{ id = 'd-1'; value = 'User.Read.All' }, @{ id = 'd-2'; value = 'Group.Read.All' })
          appRoles = @(@{ id = 'r-1'; value = 'User.Read.All' }, @{ id = 'r-2'; value = 'Group.Read.All' }) }) }
    $exoSpBody = @{ value = @(@{ id = 'sp-exo'; appId = '00000002-0000-0ff1-ce00-000000000000'; displayName = 'Office 365 Exchange Online'; oauth2PermissionScopes = @(); appRoles = @(@{ id = 'r-x'; value = 'Exchange.ManageAsApp' }) }) }
    $rt = New-Router @(
      @{ Method = 'GET'; Pattern = "appId eq '00000003-"; Body = $graphSpBody },
      @{ Method = 'GET'; Pattern = "appId eq '00000002-"; Body = $exoSpBody },
      @{ Method = 'GET'; Pattern = 'v1\.0/applications\?'; Body = @{ value = @() } }
    )
    Set-GraphRestTestHook -Transport $rt.Transport
    $od = Join-Path $TempRoot 'e2e-app-reg'
    $r = Invoke-Tool 'tools/New-AgentReadOnlyApp.ps1' @{ TenantId = $tenant; DelegatedPermissions = @('User.Read.All', 'Group.Read.All'); ApplicationPermissions = @('User.Read.All', 'Group.Read.All'); IncludeExchange = $true; OutDir = $od }
    Assert-Equal 0 $r.Exit $r.Out
    Assert-True ($r.Out -match 'DRY RUN') $r.Out
    Assert-True ($r.Out -match 'read-only, not least-privilege') $r.Out
    $plan = Get-Content (Join-Path $od 'plan.json') -Raw | ConvertFrom-Json
    Assert-Equal 5 $plan.permissionEntries
    Assert-Equal 'off' $plan.publicClientFlows
    Assert-Equal 0 @($rt.Log | Where-Object Method -ne 'GET').Count
    Assert-Throws { & (Join-Path $repoRoot 'tools' 'New-AgentReadOnlyApp.ps1') -TenantId $tenant -DelegatedPermissions 'User.ReadWrite.All' } '*Refusing non-read-only*'
    Assert-Throws { & (Join-Path $repoRoot 'tools' 'New-AgentReadOnlyApp.ps1') -TenantId $tenant -ApplicationPermissions 'Sites.Read.All' } '*Refusing application*'
  }

  Test-Case 'e2e Invoke-OnboardingGates.ps1: dry run writes nothing; -Apply writes and reads back every gate' {
    $skuId = '00000000-0000-4000-8000-00000000e3e3'
    $st = @{ Location = $null; Licenses = @(); Phones = @() }
    $routes = @(
      @{ Method = 'GET'; Pattern = 'v1\.0/users\?\$filter=userPrincipalName'; Body = { param($q) @{ value = @(@{ id = 'u-new'; userPrincipalName = 'new.hire@contoso.onmicrosoft.com'; accountEnabled = $true; onPremisesSyncEnabled = $true; usageLocation = $st.Location }) } }.GetNewClosure() },
      @{ Method = 'GET'; Pattern = 'users/u-new\?\$select=usageLocation'; Body = { param($q) @{ usageLocation = $st.Location } }.GetNewClosure() },
      @{ Method = 'PATCH'; Pattern = 'users/u-new$'; Status = 204; Body = { param($q) $st.Location = ($q.Body | ConvertFrom-Json).usageLocation; $null }.GetNewClosure() },
      @{ Method = 'GET'; Pattern = 'subscribedSkus'; Body = @{ value = @(@{ skuId = $skuId; skuPartNumber = 'SPE_E3'; prepaidUnits = @{ enabled = 10 }; consumedUnits = 7 }) } },
      @{ Method = 'GET'; Pattern = 'users/u-new/licenseDetails'; Body = { param($q) @{ value = @($st.Licenses) } }.GetNewClosure() },
      @{ Method = 'POST'; Pattern = 'users/u-new/assignLicense'; Body = { param($q) $st.Licenses = @(@{ skuId = $skuId; skuPartNumber = 'SPE_E3'; servicePlans = @(@{ servicePlanName = 'EXCHANGE_S_ENTERPRISE'; provisioningStatus = 'PendingProvisioning' }) }); @{ id = 'u-new' } }.GetNewClosure() },
      @{ Method = 'GET'; Pattern = 'users/u-new/authentication/phoneMethods'; Body = { param($q) @{ value = @($st.Phones) } }.GetNewClosure() },
      @{ Method = 'POST'; Pattern = 'users/u-new/authentication/phoneMethods'; Status = 201; Body = { param($q) $st.Phones = @(@{ id = 'p1'; phoneType = 'mobile' }); @{ id = 'p1' } }.GetNewClosure() }
    )
    $rt = New-Router $routes
    Set-GraphRestTestHook -Transport $rt.Transport
    $common = @{ TenantId = $tenant; UserPrincipalName = 'new.hire@contoso.onmicrosoft.com'; SkuPartNumber = 'SPE_E3'; MobilePhone = '+1 5555550123' }
    $dry = Invoke-Tool 'recipes/Invoke-OnboardingGates.ps1' $common
    Assert-Equal 0 $dry.Exit $dry.Out
    Assert-True ($dry.Out -match 'LOCATION\s+WOULD') $dry.Out
    Assert-True ($dry.Out -match 'LICENSE\s+WOULD') $dry.Out
    Assert-Equal 0 @($rt.Log | Where-Object Method -ne 'GET').Count 'dry run sent no writes'
    $apply = Invoke-Tool 'recipes/Invoke-OnboardingGates.ps1' ($common + @{ Apply = $true })
    Assert-Equal 0 $apply.Exit $apply.Out
    foreach ($g in 'SYNC', 'LOCATION', 'SEATS', 'LICENSE', 'MFA') { Assert-True ($apply.Out -match "$g\s+PASS") "$g should pass: $($apply.Out)" }
    Assert-True ($apply.Out -match 'EXCHANGE_S_ENTERPRISE=PendingProvisioning') 'reports a plan that is still provisioning'
    $lic = @($rt.Log | Where-Object { $_.Method -eq 'POST' -and $_.Uri -like '*assignLicense' })[0]
    Assert-True ($lic.Body -like '*"addLicenses":*' -and $lic.Body -like '*"removeLicenses":*') 'explicit add and remove arrays'
  }

  Test-Case 'e2e Export-AutopilotIdentities.ps1 -CheckManagedDevice flags identities whose Intune record is gone' {
    $rt = New-Router @(
      @{ Method = 'GET'; Pattern = 'windowsAutopilotDeviceIdentities'; Body = @{ value = @(
            @{ serialNumber = 'SN0001'; managedDeviceId = '00000000-0000-4000-8000-0000000000e1'; enrollmentState = 'notContacted' },
            @{ serialNumber = 'SN0002'; managedDeviceId = '00000000-0000-4000-8000-0000000000e2'; enrollmentState = 'enrolled' }) } },
      @{ Method = 'GET'; Pattern = 'deviceManagement/managedDevices\?'; Body = @{ value = @(@{ id = '00000000-0000-4000-8000-0000000000e2' }) } }
    )
    Set-GraphRestTestHook -Transport $rt.Transport
    $od = Join-Path $TempRoot 'e2e-ap'
    $r = Invoke-Tool 'recipes/Export-AutopilotIdentities.ps1' @{ TenantId = $tenant; CheckManagedDevice = $true; OutDir = $od }
    $rows = @(Import-Csv (Get-ChildItem $od -Filter '*.csv' | Select-Object -First 1).FullName)
    Assert-Equal 'True' ($rows | Where-Object SerialNumber -eq 'SN0001').ManagedDeviceMissing
    Assert-Equal 'False' ($rows | Where-Object SerialNumber -eq 'SN0002').ManagedDeviceMissing
    Assert-True ($r.Out -match 'no longer exists: 1') $r.Out
  }

  $env:LOCALAPPDATA = $savedLocal
  Set-GraphRestTestHook

  Test-Case 'e2e Start-QueueWorker.ps1 (no sign-in): runs steps in order, carries variables, records errors, stops on STOP' {
    $wd = Join-Path $TempRoot 'worker'
    $q = Join-Path $wd 'queue'
    New-Item -ItemType Directory -Force -Path $q | Out-Null
    '$carried = 41; "step ten ran"' | Set-Content (Join-Path $q '10-first.ps1')
    '"carried is $($carried + 1)"' | Set-Content (Join-Path $q '20-second.ps1')
    '"before the failure, line one"; Write-Host "before the failure, line two"; throw "synthetic failure"' | Set-Content (Join-Path $q '30-fails.ps1')
    "New-Item -ItemType File -Path '$(Join-Path $wd 'STOP')' | Out-Null; 'stopping'" | Set-Content (Join-Path $q '40-stop.ps1')
    'not a step' | Set-Content (Join-Path $q 'readme.ps1')
    $pwshPath = (Get-Process -Id $PID).Path
    $null = & $pwshPath -NoProfile -NonInteractive -Command "`$env:M365AGENTOPS_OFFLINE='1'; & '$(Join-Path $repoRoot 'tools' 'Start-QueueWorker.ps1')' -TenantId contoso.onmicrosoft.com -WorkDir '$wd' -NoGraph -IdleMinutes 1" 2>&1
    Assert-Equal 0 $LASTEXITCODE
    Assert-True ((Get-Content (Join-Path $q '20-second.ps1.out.txt') -Raw) -match 'carried is 42') 'variables carry between dot-sourced steps'
    Assert-True ((Get-Content (Join-Path $q '10-first.ps1.done') -Raw) -match '^\S+ OK sha256=[0-9A-F]{64}') 'done marker has outcome and hash'
    Assert-True ((Get-Content (Join-Path $q '30-fails.ps1.done') -Raw) -match 'TERMINATING_ERROR') 'failure recorded'
    $failOut = Get-Content (Join-Path $q '30-fails.ps1.out.txt') -Raw
    Assert-True ($failOut -match 'line one' -and $failOut -match 'line two' -and $failOut -match 'TERMINATING ERROR') "output before the error is kept: $failOut"
    Assert-True (-not (Test-Path (Join-Path $q 'readme.ps1.done'))) 'files not named NN-name.ps1 are ignored'
    $status = Get-Content (Join-Path $wd 'worker-status.txt') -Raw
    Assert-True ($status -match 'READY' -and $status -match 'STOP seen') $status
    Assert-True ($status -match 'stops at \d\d:\d\d:\d\d, the session limit of 55 minutes') 'no token held: the session limit applies'
    Assert-True (@(Get-ChildItem $wd -Filter 'worker-transcript-*.txt').Count -eq 1) 'transcript written'
  }
}

#endregion

Set-DeviceAuthTestHook
Set-GraphRestTestHook
Clear-GraphRestContext
Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
Write-Host "Passed: $script:Passed  Failed: $($script:Failed.Count)"
if ($script:Failed.Count) { $script:Failed | ForEach-Object { Write-Host "  - $_" } }
exit $script:Failed.Count
