#Requires -Version 7.2
<#
.SYNOPSIS
  Read-only Microsoft Graph runner for an agent. GET only, follows every @odata.nextLink, retries 429 and 503
  with Retry-After, and writes one JSON file per query.

.DESCRIPTION
  Uses the access token cached by auth/Start-DeviceLogin.ps1 for the chosen profile and never starts a sign-in
  itself. The REST layer is put in read-only mode, so there is no code path in this script that can send a
  POST, PATCH, PUT or DELETE. Relative URIs must start with v1.0/ or beta/; absolute URIs must be on
  graph.microsoft.com, and so must every nextLink.

  Output: <OutDir>\q01.json, q02.json ... and summary.json. Exit code 0 when every query succeeded, 3 otherwise.

.EXAMPLE
  pwsh -File tools/Invoke-GraphRead.ps1 -TenantId contoso.onmicrosoft.com `
    -Uri 'v1.0/users?$select=id,displayName,accountEnabled&$top=999', 'v1.0/groups?$filter=securityEnabled eq true&$select=id,displayName'
.EXAMPLE
  pwsh -File tools/Invoke-GraphRead.ps1 -TenantId contoso.onmicrosoft.com -AuthProfile IntuneRead `
    -Uri 'v1.0/deviceManagement/managedDevices?$select=deviceName,operatingSystem,lastSyncDateTime'
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string] $TenantId,
  [Parameter(Mandatory)][string[]] $Uri,
  [ValidateSet('GraphRead', 'IntuneRead')][string] $AuthProfile = 'GraphRead',
  [string] $OutDir,
  [switch] $ConsistencyLevelEventual,
  [ValidateRange(1, 5000)][int] $MaxPages = 200
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'auth' 'DeviceCodeAuth.psm1')
Import-Module (Join-Path $repoRoot 'lib' 'AgentGraph.psm1')

if (-not $OutDir) { $OutDir = Join-Path $repoRoot 'out' "graph-read-$(Get-Date -Format yyyyMMdd-HHmmss)" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$tok = Get-AgentAccessToken -TenantId $TenantId -AuthProfile $AuthProfile -CacheOnly
Set-GraphRestContext -AccessToken $tok.AccessToken
$headers = if ($ConsistencyLevelEventual) { @{ ConsistencyLevel = 'eventual' } } else { @{} }

$summary = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($u in $Uri) {
  $i++
  $file = Join-Path $OutDir ('q{0:d2}.json' -f $i)
  try {
    $items = @(Get-GraphPaged -Uri $u -Headers $headers -MaxPages $MaxPages)
    [pscustomobject]@{ uri = $u; retrievedUtc = (Get-Date).ToUniversalTime().ToString('o'); count = $items.Count; value = $items } |
      ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $file -Encoding utf8
    $summary.Add([pscustomobject]@{ query = $i; uri = $u; status = 'OK'; httpStatus = 200; count = $items.Count })
    Write-Output ('q{0:d2} OK {1} rows :: {2}' -f $i, $items.Count, $u)
  } catch {
    $status = Get-GraphErrorStatus $_
    [pscustomobject]@{ uri = $u; error = $_.Exception.Message; httpStatus = $status } |
      ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $file -Encoding utf8
    $summary.Add([pscustomobject]@{ query = $i; uri = $u; status = 'ERROR'; httpStatus = $status; count = 0 })
    Write-Output ('q{0:d2} ERR {1} :: {2} :: {3}' -f $i, $status, $u, $_.Exception.Message)
  }
}
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutDir 'summary.json') -Encoding utf8
Write-Output "OUT_DIR=$OutDir"
if (@($summary | Where-Object status -ne 'OK').Count -gt 0) { exit 3 }
