#Requires -Version 7.2
<#
.SYNOPSIS
  Read-only diagnostic: can interactive or WAM sign-in work from the process this runs in?

.DESCRIPTION
  Inside an AI agent's shell tool, PowerShell runs as a non-interactive child process. The Windows Web Account
  Manager (WAM) broker needs a parent window to show its prompt, and the SDK's interactive browser credential
  needs an interactive session. When both are missing, Connect-MgGraph fails with errors like
  "window handle must be configured" even though a browser is sitting right there on the desktop.
  The problem is the process context, not the machine.

  This script reports the facts that decide it: interactive flag, console window handle, redirected streams,
  Windows session id, elevation, parent process, Graph SDK version and options, and whether a Graph SDK token
  cache folder exists (file names and sizes only).

  By default it changes nothing. It does not call Set-MgGraphOption, because -DisableLoginByWAM is a persistent
  per-user setting. -TryGraphConnect is different: it attempts a real Connect-MgGraph in a separate child
  process with a timeout, reports the error text, and kills the child if it hangs. In a console that can show
  UI, that opens a real sign-in, and possibly a consent prompt for User.Read.

.EXAMPLE
  pwsh -NoProfile -File auth/Test-WamSignIn.ps1
.EXAMPLE
  pwsh -NoProfile -File auth/Test-WamSignIn.ps1 -TryGraphConnect -TenantId contoso.onmicrosoft.com
#>
[CmdletBinding()]
param(
  [switch] $TryGraphConnect,
  [string] $TenantId,
  [ValidateRange(10, 300)][int] $TimeoutSeconds = 45
)
$ErrorActionPreference = 'Stop'

$report = [ordered]@{
  generatedUtc       = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
  psVersion          = $PSVersionTable.PSVersion.ToString()
  os                 = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
  processId          = $PID
  parentProcess      = $null
  userInteractive    = [Environment]::UserInteractive
  stdinRedirected    = [Console]::IsInputRedirected
  stdoutRedirected   = [Console]::IsOutputRedirected
  consoleWindow      = $null
  sessionId          = $null
  elevated           = $null
  graphSdkVersion    = $null
  graphOptions       = $null
  graphTokenCacheDir = $null
  tryConnect         = $null
  hints              = @()
}

try { $report.parentProcess = (Get-Process -Id $PID).Parent.ProcessName } catch { $report.parentProcess = '(unknown)' }

if ($IsWindows) {
  $report.sessionId = (Get-Process -Id $PID).SessionId
  try {
    if (-not ('AgentOps.NativeConsole' -as [type])) {
      Add-Type -Namespace AgentOps -Name NativeConsole -MemberDefinition '[DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow();'
    }
    $h = [AgentOps.NativeConsole]::GetConsoleWindow()
    $report.consoleWindow = if ($h -eq [IntPtr]::Zero) { 'none' } else { 'present' }
  } catch { $report.consoleWindow = '(could not query)' }
  $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $report.elevated = ([System.Security.Principal.WindowsPrincipal]::new($id)).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
  $cacheDir = Join-Path $env:LOCALAPPDATA '.IdentityService'
  if (Test-Path -LiteralPath $cacheDir) {
    $report.graphTokenCacheDir = @(Get-ChildItem -LiteralPath $cacheDir -Force -File | Select-Object Name, Length, @{ n = 'LastWriteUtc'; e = { $_.LastWriteTimeUtc.ToString('s') } })
  } else {
    $report.graphTokenCacheDir = 'absent'
  }
}

$mod = Get-Module -ListAvailable Microsoft.Graph.Authentication | Sort-Object Version -Descending | Select-Object -First 1
if ($mod) {
  $report.graphSdkVersion = $mod.Version.ToString()
  try {
    Import-Module $mod.Path -ErrorAction Stop
    if (Get-Command Get-MgGraphOption -ErrorAction SilentlyContinue) { $report.graphOptions = Get-MgGraphOption }
  } catch { $report.graphOptions = "(could not load: $($_.Exception.Message))" }
} else {
  $report.graphSdkVersion = 'not installed'
}

if ($TryGraphConnect) {
  if (-not $TenantId) { throw '-TryGraphConnect needs -TenantId.' }
  if (-not $mod) { throw 'Microsoft.Graph.Authentication is not installed.' }
  $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "wam-probe-$PID"
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  $probe = Join-Path $tmp 'probe.ps1'
  $out = Join-Path $tmp 'probe-out.txt'
  @"
`$ErrorActionPreference = 'Stop'
try {
  Import-Module Microsoft.Graph.Authentication
  Connect-MgGraph -TenantId '$($TenantId -replace "'", "''")' -Scopes 'User.Read' -ContextScope Process -NoWelcome
  `$c = Get-MgContext
  "CONNECTED authType=`$(`$c.AuthType) tokenCredentialType=`$(`$c.TokenCredentialType)"
} catch { "FAILED `$(`$_.Exception.Message)" }
"@ | Set-Content -LiteralPath $probe -Encoding utf8
  $p = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList "-NoProfile -NonInteractive -File `"$probe`"" -RedirectStandardOutput $out -PassThru -NoNewWindow
  if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
    try { $p.Kill($true) } catch { }
    $report.tryConnect = "TIMED OUT after $TimeoutSeconds s (no prompt could be shown, or it waited for input)"
  } else {
    $report.tryConnect = (Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue).Trim()
  }
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

$hints = [System.Collections.Generic.List[string]]::new()
if (-not $report.userInteractive -or $report.consoleWindow -eq 'none' -or $report.stdinRedirected) {
  $hints.Add('This process has no interactive window to parent a WAM or browser prompt. Use device code: auth/Start-DeviceLogin.ps1.')
}
if ($report.sessionId -eq 0) { $hints.Add('Session 0 is a services session. Interactive sign-in cannot work here.') }
if ($report.elevated) { $hints.Add('Elevated shell: if it runs as a separate admin account, its token caches are separate from your normal shell''s, and tools run from the agent will not see them.') }
if ($report.tryConnect -and $report.tryConnect -match 'window handle') { $hints.Add('Matches the WAM parent-window failure. Device code avoids it.') }
$report.hints = $hints.ToArray()

[pscustomobject]$report | ConvertTo-Json -Depth 6
