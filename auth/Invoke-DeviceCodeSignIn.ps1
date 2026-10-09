#Requires -Version 7.2
<#
.SYNOPSIS
  Child process body for Start-DeviceLogin.ps1. Not meant to be run by hand.

.DESCRIPTION
  Runs the device authorization grant for one profile, writes the user code line to -UserCodeFile the moment it
  exists, waits for the human to finish sign-in, caches the access token (DPAPI), and appends the outcome to
  -StatusFile. The status file never contains a token or a device code.

  It also records how many scopes the token actually carries versus how many the profile asked for. With the
  shared first-party Graph client those numbers differ, which is the whole argument in docs/scopes-and-roles.md.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string] $TenantId,
  [Parameter(Mandatory)][string] $AuthProfile,
  [Parameter(Mandatory)][string] $StateDir,
  [Parameter(Mandatory)][string] $UserCodeFile,
  [Parameter(Mandatory)][string] $StatusFile
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'DeviceCodeAuth.psm1') -Force

function Write-Status([string] $Message) {
  Add-Content -LiteralPath $StatusFile -Value "$(Get-Date -Format s) $Message" -Encoding utf8
}

Write-Status "STARTED profile=$AuthProfile pid=$PID"
try {
  $profileInfo = Get-AgentAuthProfile -Name $AuthProfile
  $t = Get-AgentAccessToken -TenantId $TenantId -AuthProfile $AuthProfile -StateDir $StateDir -UserCodeFile $UserCodeFile
  $requested = @($profileInfo.Scopes).Count
  $granted = @($t.GrantedScopes).Count
  Write-Status "OK profile=$AuthProfile source=$($t.Source) requestedScopes=$requested grantedScopes=$granted"
  if ($granted -gt $requested) {
    Write-Status "NOTE the token carries $granted scopes for $requested requested. Consented scopes accumulate on a shared client; your directory roles are the real limit."
  }
  exit 0
} catch {
  Write-Status "FAIL $($_.Exception.Message)"
  exit 1
}
