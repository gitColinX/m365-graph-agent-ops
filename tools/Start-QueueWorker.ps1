#Requires -Version 7.2
<#
.SYNOPSIS
  One sign-in, many steps. A long-running PowerShell worker that signs in to Microsoft Graph (and optionally
  Exchange Online) once, then runs each NN-name.ps1 the agent drops into <WorkDir>\queue, in name order.

.DESCRIPTION
  The agent launches this detached, relays the user code(s) from usercode-graph.txt and usercode-exo.txt, and
  then works by writing small step scripts into the queue: 10-discovery.ps1, 20-remediate.ps1,
  30-verify.ps1. For each step the worker records the SHA-256 of the file, dot-sources it (so variables carry
  from one step to the next), appends everything it prints to <step>.out.txt as it is printed (so the output
  before a terminating error is kept), and drops a <step>.done marker with the time, the outcome and the hash.
  The whole session is transcribed. Creating <WorkDir>\STOP ends it.

  Where the human gate is: this worker runs whatever lands in the queue, as me. The rule is the one in the
  README's guardrail 11: I approve production writes before they run. A step that writes is approved when the
  agent writes its file, before the step exists in the queue. Routine reads may run under Claude Code's auto
  mode, whose classifier approves them, but keep writes into the queue folder out of any auto-approval.

  Bounds: the worker stops before the earliest of: -MaxSessionMinutes after it started (default 55), or the
  not-after time of any token it holds. A cached token can already be most of the way through its life when
  the worker starts, so the limit is counted from when the token was issued, not from the worker's start.
  It also stops after -IdleMinutes without a step.

  What -AllowWrites does and does not do: Graph REST calls through lib/AgentGraph.psm1 are read-only unless
  -AllowWrites is passed. That is an accident guard, not a security boundary. A step runs as me in this
  process, so it could switch the REST layer to writes itself or use the connected Graph SDK and Exchange
  cmdlets, which that switch never covered. The controls are my approval of each step that writes, the token's
  scopes and my directory roles. The token variables are removed from the step scope after sign-in, which keeps them out
  of casual reach, nothing more.

.EXAMPLE
  # launched by the agent, detached:
  Start-Process pwsh -ArgumentList '-NoProfile -NonInteractive -File tools/Start-QueueWorker.ps1 -TenantId contoso.onmicrosoft.com -WorkDir C:\work\case-001 -ExchangeUserPrincipalName admin@contoso.onmicrosoft.com' -WindowStyle Hidden
  # then: read C:\work\case-001\usercode-graph.txt, relay the code, wait for READY in worker-status.txt,
  # write C:\work\case-001\queue\10-discovery.ps1, read 10-discovery.ps1.out.txt when the .done marker appears.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string] $TenantId,
  [Parameter(Mandatory)][string] $WorkDir,
  [string] $GraphProfile = 'GraphRead',
  [string] $ExchangeUserPrincipalName,
  [switch] $NoGraph,
  [switch] $AllowWrites,
  [ValidateRange(5, 85)][int] $MaxSessionMinutes = 55,
  [ValidateRange(1, 240)][int] $IdleMinutes = 30
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'auth' 'DeviceCodeAuth.psm1')
Import-Module (Join-Path $repoRoot 'lib' 'AgentGraph.psm1')

$queue = Join-Path $WorkDir 'queue'
New-Item -ItemType Directory -Force -Path $queue | Out-Null
$statusFile = Join-Path $WorkDir 'worker-status.txt'
$stopFile = Join-Path $WorkDir 'STOP'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
Start-Transcript -Path (Join-Path $WorkDir "worker-transcript-$stamp.txt") -Force | Out-Null

# Say never writes to the pipeline. Functions that return a token must not have status mixed into their output.
function Say([string] $Message) {
  $line = "$(Get-Date -Format HH:mm:ss) $Message"
  Add-Content -LiteralPath $statusFile -Value $line -Encoding utf8
  Write-Host $line
}

$exitCode = 0
$started = [datetimeoffset]::Now
$tokenNotAfter = [System.Collections.Generic.List[object]]::new()
try {
  Say "STARTING pid=$PID tenant=$TenantId graphProfile=$(if ($NoGraph) { 'none' } else { $GraphProfile }) exchange=$([bool]$ExchangeUserPrincipalName) allowWrites=$([bool]$AllowWrites)"
  if (-not $NoGraph) {
    $codeFile = Join-Path $WorkDir 'usercode-graph.txt'
    Say "GRAPH sign-in: if a code is needed it appears in $codeFile"
    $g = Get-AgentAccessToken -TenantId $TenantId -AuthProfile $GraphProfile -UserCodeFile $codeFile
    $tokenNotAfter.Add($g.NotAfter)
    Set-GraphRestContext -AccessToken $g.AccessToken -AllowWrites:$AllowWrites
    Say "GRAPH token ready (source=$($g.Source), usable until $($g.NotAfter.ToLocalTime().ToString('HH:mm:ss'))); REST layer readOnly=$((Get-GraphRestMode).ReadOnly)"
    if (Get-Module -ListAvailable Microsoft.Graph.Authentication) {
      $ctx = Connect-AgentGraph -AccessToken $g.AccessToken
      Say "GRAPH SDK connected as $($ctx.Account) (token carries $($ctx.ScopeCount) scopes)"
    } else {
      Say 'GRAPH SDK not installed; steps can use Invoke-GraphRest and Get-GraphPaged only'
    }
    Remove-Variable -Name g -ErrorAction SilentlyContinue
  }
  if ($ExchangeUserPrincipalName) {
    $codeFile = Join-Path $WorkDir 'usercode-exo.txt'
    Say "EXO sign-in: if a code is needed it appears in $codeFile"
    $e = Get-AgentAccessToken -TenantId $TenantId -AuthProfile Exchange -UserCodeFile $codeFile
    $tokenNotAfter.Add($e.NotAfter)
    $ci = Connect-AgentExchange -AccessToken $e.AccessToken -UserPrincipalName $ExchangeUserPrincipalName
    Say "EXO connected via access token as $($ci.UserPrincipalName) (usable until $($e.NotAfter.ToLocalTime().ToString('HH:mm:ss')))"
    Remove-Variable -Name e -ErrorAction SilentlyContinue
  }
} catch {
  Say "FAIL during sign-in: $($_.Exception.Message)"
  Stop-Transcript | Out-Null
  exit 1
}

$ErrorActionPreference = 'Continue'
$limit = Get-SessionDeadline -Start $started -MaxSessionMinutes $MaxSessionMinutes -TokenNotAfter $tokenNotAfter.ToArray()
$lastActivity = Get-Date
Say "READY queue=$queue (drop NN-name.ps1; create STOP to end; stops at $($limit.Deadline.ToLocalTime().ToString('HH:mm:ss')), the $($limit.Reason); idle limit $IdleMinutes min)"
while (-not (Test-Path -LiteralPath $stopFile)) {
  if ([datetimeoffset]::Now -ge $limit.Deadline) {
    Say "SESSION LIMIT reached ($($limit.Reason)); stopping so no step runs on an expiring token. Sign in again and start a new worker to continue."
    $exitCode = 2
    break
  }
  $next = Get-NextQueueStep -QueueDir $queue
  if (-not $next) {
    if (((Get-Date) - $lastActivity).TotalMinutes -ge $IdleMinutes) { Say 'IDLE LIMIT reached; stopping.'; break }
    Start-Sleep -Seconds 1
    continue
  }
  $hash = (Get-FileHash -LiteralPath $next.FullName -Algorithm SHA256).Hash
  $outFile = "$($next.FullName).out.txt"
  Say "RUN $($next.Name) sha256=$hash"
  $errorsBefore = $Error.Count
  $outcome = 'OK'
  # Each line is appended the moment it is produced. Buffering the whole step (Out-String at the end) loses
  # everything a step printed before a terminating error, which is exactly the output needed afterwards.
  [System.IO.File]::WriteAllText($outFile, '')
  try {
    . $next.FullName *>&1 | Out-String -Stream -Width 300 |
      ForEach-Object { [System.IO.File]::AppendAllText($outFile, $_ + [Environment]::NewLine) }
  } catch {
    $outcome = 'TERMINATING_ERROR'
    [System.IO.File]::AppendAllText($outFile, "TERMINATING ERROR: $($_ | Out-String)")
  }
  if ($outcome -eq 'OK' -and $Error.Count -gt $errorsBefore) { $outcome = "OK_WITH_ERRORS($($Error.Count - $errorsBefore))" }
  Set-Content -LiteralPath "$($next.FullName).done" -Value "$(Get-Date -Format s) $outcome sha256=$hash" -Encoding utf8
  Say "DONE $($next.Name) $outcome"
  $lastActivity = Get-Date
}
if (Test-Path -LiteralPath $stopFile) { Say 'STOP seen' }
Say 'Disconnecting'
if ($ExchangeUserPrincipalName) { try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch { } }
if (-not $NoGraph -and (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue)) { try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { } }
Clear-GraphRestContext
Stop-Transcript | Out-Null
exit $exitCode
