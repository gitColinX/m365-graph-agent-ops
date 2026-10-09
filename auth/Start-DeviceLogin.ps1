#Requires -Version 7.2
<#
.SYNOPSIS
  Agent-facing sign-in launcher. Starts the device code flow in a detached PowerShell process and returns as soon
  as the user code exists, so the agent can relay the code to the human. My first detached launcher, which used
  the SDK's device code sign-in, got the code to me in about 3 seconds; this child makes a single POST before
  writing the code.

.DESCRIPTION
  Why detached: an agent's shell tool hands back output only when the command finishes. A device code sign-in run
  in the foreground keeps the code invisible to the agent until the sign-in is already over or has timed out.

  The child process (Invoke-DeviceCodeSignIn.ps1) polls the token endpoint for the full lifetime of the code
  (15 minutes in Entra ID), writes the access token to the DPAPI cache and records the outcome in a status file.
  Every later tool run, in any process, reuses that cached token until it ages out (50 minutes by default).

  Nothing secret is printed. The user code is single-use and worthless without the device_code, which never
  leaves the child's memory.

.PARAMETER AuthProfile
  One of the profiles in auth/DeviceCodeAuth.psm1 (GraphRead, IntuneRead, IntuneAppWrite, AppRoleWrite,
  AppRegistration, Onboarding, GuestInvite, GroupWrite, Exchange).

.PARAMETER Force
  Ignore and delete any cached token for this profile and start a fresh sign-in.

.EXAMPLE
  pwsh -NoProfile -File auth/Start-DeviceLogin.ps1 -TenantId contoso.onmicrosoft.com -AuthProfile GraphRead

  USER_CODE=ABCD1234 URL=https://microsoft.com/devicelogin EXPIRES_IN=900 PROFILE=GraphRead
  CHILD_PID=12345
  STATUS_FILE=C:\Users\me\AppData\Local\m365-graph-agent-ops\signin-GraphRead-20260101-120000\status.txt
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string] $TenantId,
  [Parameter(Mandatory)][string] $AuthProfile,
  [string] $StateDir,
  [ValidateRange(5, 120)][int] $WaitSeconds = 30,
  [switch] $Force
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'DeviceCodeAuth.psm1') -Force
if (-not $StateDir) { $StateDir = Get-DefaultStateDir }
$null = Get-AgentAuthProfile -Name $AuthProfile
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

$cachePath = Get-TokenCachePath -TenantId $TenantId -AuthProfile $AuthProfile -StateDir $StateDir
if ($Force) {
  Remove-AccessTokenCache -Path $cachePath
} else {
  $cached = Read-AccessTokenCache -Path $cachePath
  if ($cached) {
    $age = [int]((Get-Date) - (Get-Item -LiteralPath $cachePath).LastWriteTime).TotalMinutes
    $notAfter = Get-AccessTokenCacheNotAfter -Path $cachePath
    Write-Output "CACHED_TOKEN PROFILE=$AuthProfile AGE_MINUTES=$age USABLE_UNTIL=$($notAfter.ToLocalTime().ToString('HH:mm')) (no sign-in needed)"
    return
  }
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDir = Join-Path $StateDir "signin-$AuthProfile-$stamp"
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
$userCodeFile = Join-Path $runDir 'usercode.txt'
$statusFile = Join-Path $runDir 'status.txt'
$stdoutFile = Join-Path $runDir 'child-stdout.txt'
$stderrFile = Join-Path $runDir 'child-stderr.txt'
$childScript = Join-Path $PSScriptRoot 'Invoke-DeviceCodeSignIn.ps1'

function ConvertTo-QuotedArg([string] $a) { '"' + ($a -replace '"', '\"') + '"' }
$childArgs = @(
  '-NoProfile', '-NonInteractive', '-File', (ConvertTo-QuotedArg $childScript),
  '-TenantId', (ConvertTo-QuotedArg $TenantId), '-AuthProfile', (ConvertTo-QuotedArg $AuthProfile),
  '-StateDir', (ConvertTo-QuotedArg $StateDir), '-UserCodeFile', (ConvertTo-QuotedArg $userCodeFile),
  '-StatusFile', (ConvertTo-QuotedArg $statusFile)
) -join ' '

$sp = @{
  FilePath               = (Get-Process -Id $PID).Path
  ArgumentList           = $childArgs
  RedirectStandardOutput = $stdoutFile
  RedirectStandardError  = $stderrFile
  PassThru               = $true
}
if ($IsWindows) { $sp.WindowStyle = 'Hidden' }
$child = Start-Process @sp

$deadline = (Get-Date).AddSeconds($WaitSeconds)
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Milliseconds 250
  if (Test-Path -LiteralPath $userCodeFile) {
    $line = (Get-Content -LiteralPath $userCodeFile -Raw -ErrorAction SilentlyContinue)
    if ($line) {
      Write-Output $line.Trim()
      Write-Output "CHILD_PID=$($child.Id)"
      Write-Output "STATUS_FILE=$statusFile"
      Write-Output 'NEXT: the human opens the URL, enters the code, and completes MFA. Then check STATUS_FILE for OK.'
      return
    }
  }
  if ($child.HasExited) {
    Write-Output 'Sign-in process exited before a code was issued.'
    if (Test-Path -LiteralPath $statusFile) { Get-Content -LiteralPath $statusFile | Write-Output }
    if (Test-Path -LiteralPath $stderrFile) { Get-Content -LiteralPath $stderrFile -Tail 20 | Write-Output }
    exit 1
  }
}
Write-Output "Timed out after $WaitSeconds s waiting for a user code. The child (PID $($child.Id)) is still running."
if (Test-Path -LiteralPath $statusFile) { Get-Content -LiteralPath $statusFile | Write-Output }
exit 1
