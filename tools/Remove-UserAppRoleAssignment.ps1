#Requires -Version 7.2
<#
.SYNOPSIS
  Removes one user's DIRECT app role assignment, and refuses anything that is really a group's grant.

.DESCRIPTION
  GET /users/{id}/appRoleAssignments returns the user's own grants AND the grants made to groups the user is a
  direct member of. A group-conveyed row looks almost the same: same resource, same app role, but
  principalType 'Group' and the group's id as principalId. Deleting that row through the service principal's
  appRoleAssignedTo collection removes the app for every member of the group. I did exactly that once, to an
  All Users grant, and restored it about two minutes later (docs/case-studies/approle-delete-blast-radius.md).

  This helper:
    1. Resolves the user to an object id (UPN keys are not accepted everywhere in Graph).
    2. Pages all of the user's appRoleAssignments and picks exactly one, by -AssignmentId or -ResourceDisplayName.
    3. Refuses unless principalType is 'User', principalId is this user, and the assignment id decodes to the
       same principal (fail closed if it does not decode). For a group grant it prints which group and how
       many members it reaches, counted by following every nextLink (not one page of 999).
    4. Dry run by default. With -Apply it snapshots the assignment to a JSONL file (enough to re-create it),
       counts the resource's assignments, DELETEs only through /users/{id}/appRoleAssignments/{id} (never
       through the service principal side), and reads back: the user's row is gone, and the resource lost
       exactly one assignment.

.EXAMPLE
  pwsh -File tools/Remove-UserAppRoleAssignment.ps1 -TenantId contoso.onmicrosoft.com -User adele.vance@contoso.onmicrosoft.com -ResourceDisplayName 'Print Portal'
.EXAMPLE
  pwsh -File tools/Remove-UserAppRoleAssignment.ps1 -TenantId contoso.onmicrosoft.com -User adele.vance@contoso.onmicrosoft.com -ResourceDisplayName 'Print Portal' -Apply
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string] $TenantId,
  [Parameter(Mandatory)][string] $User,
  [string] $ResourceDisplayName,
  [string] $AssignmentId,
  [switch] $Apply,
  [switch] $SkipIdDecodeCheck,
  [string] $OutDir
)
$ErrorActionPreference = 'Stop'
if ([bool]$ResourceDisplayName -eq [bool]$AssignmentId) { throw 'Give exactly one of -ResourceDisplayName or -AssignmentId.' }
$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'auth' 'DeviceCodeAuth.psm1')
Import-Module (Join-Path $repoRoot 'lib' 'AgentGraph.psm1')
if (-not $OutDir) { $OutDir = Join-Path $repoRoot 'out' "approle-remove-$(Get-Date -Format yyyyMMdd-HHmmss)" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$tok = Get-AgentAccessToken -TenantId $TenantId -AuthProfile AppRoleWrite -CacheOnly
Set-GraphRestContext -AccessToken $tok.AccessToken -AllowWrites:$Apply

# 1. Resolve the user to an object id
$userObj = if ($User -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
  Invoke-GraphRest -Uri "v1.0/users/$($User)?`$select=id,userPrincipalName,displayName"
} else {
  # Encoded: a guest UPN carries #EXT#, and an unencoded '#' would cut the query off.
  $hits = @(Get-GraphPaged -Uri "v1.0/users?`$filter=userPrincipalName eq '$(ConvertTo-ODataLiteral $User)'&`$select=id,userPrincipalName,displayName")
  if ($hits.Count -ne 1) { throw "Expected one user for '$User', found $($hits.Count)." }
  $hits[0]
}
$userId = [string]$userObj.id
Write-Output "USER $($userObj.userPrincipalName) id=$userId"

# 2. Pick exactly one assignment
$rows = @(Get-GraphPaged -Uri "v1.0/users/$userId/appRoleAssignments")
$pick = if ($AssignmentId) { Resolve-ExactlyOne -Items $rows -Property 'id' -Value $AssignmentId } else { Resolve-ExactlyOne -Items $rows -Property 'resourceDisplayName' -Value $ResourceDisplayName }
foreach ($r in $rows) { Write-Output ("  ROW resource='{0}' principalType={1} principal='{2}' id={3}" -f $r.resourceDisplayName, $r.principalType, $r.principalDisplayName, $r.id) }
if ($pick.Status -ne 'Resolved') {
  Write-Output "STOP $($pick.Status): $($pick.Matches) matching assignment(s). Use -AssignmentId to pick one. Nothing changed."
  exit 2
}
$a = $pick.Item

# 3. Decide
$decision = Test-AppRoleDeleteAllowed -Assignment $a -UserId $userId -SkipIdDecodeCheck:$SkipIdDecodeCheck
Write-Output "DECISION allowed=$($decision.Allowed) principalType=$($decision.PrincipalType) decodedPrincipal=$($decision.DecodedPrincipalId)"
Write-Output "DECISION $($decision.Reason)"
if (-not $decision.Allowed) {
  if ($decision.PrincipalType -eq 'Group') {
    $members = @(Get-GraphPaged -Uri "v1.0/groups/$($a.principalId)/transitiveMembers?`$select=id" -MaxPages 500)
    $isMember = [bool]($members | Where-Object { $_.id -eq $userId })
    Write-Output "BLAST RADIUS group '$($a.principalDisplayName)' reaches $($members.Count) members (all pages). Target user is a member: $isMember."
    Write-Output 'To remove the user''s access, remove them from that group (or exclude them), not the group''s grant.'
  }
  exit 3
}

$resourceRowsBefore = @(Get-GraphPaged -Uri "v1.0/servicePrincipals/$($a.resourceId)/appRoleAssignedTo?`$select=id,principalId,principalType")
Write-Output "RESOURCE '$($a.resourceDisplayName)' has $($resourceRowsBefore.Count) assignment(s) before."
if (-not $Apply) {
  Write-Output 'DRY RUN. Nothing was deleted. Re-run with -Apply.'
  exit 0
}

# 4. Snapshot, delete through the user path only, read back
$snap = [ordered]@{
  takenUtc      = (Get-Date).ToUniversalTime().ToString('o')
  assignment    = $a
  restoreMethod = 'POST'
  restoreUri    = "v1.0/servicePrincipals/$($a.resourceId)/appRoleAssignedTo"
  restoreBody   = [ordered]@{ principalId = $a.principalId; resourceId = $a.resourceId; appRoleId = $a.appRoleId }
}
($snap | ConvertTo-Json -Depth 8 -Compress) | Add-Content -LiteralPath (Join-Path $OutDir 'deleted-assignments.jsonl') -Encoding utf8
Invoke-GraphRest -Method DELETE -Uri "v1.0/users/$userId/appRoleAssignments/$($a.id)" | Out-Null
Start-Sleep -Seconds 2
$userRowsAfter = @(Get-GraphPaged -Uri "v1.0/users/$userId/appRoleAssignments")
$resourceRowsAfter = @(Get-GraphPaged -Uri "v1.0/servicePrincipals/$($a.resourceId)/appRoleAssignedTo?`$select=id,principalId,principalType")
$gone = -not ($userRowsAfter | Where-Object { $_.id -eq $a.id })
$lostIds = @($resourceRowsBefore | Where-Object { $resourceRowsAfter.id -notcontains $_.id } | ForEach-Object { $_.id })
$exactlyOne = ($lostIds.Count -eq 1 -and $lostIds[0] -eq $a.id)
Write-Output "READBACK user row gone: $gone"
Write-Output "READBACK resource assignments $($resourceRowsBefore.Count) -> $($resourceRowsAfter.Count); only the target removed: $exactlyOne"
Write-Output "RESTORE if needed: POST $($snap.restoreUri) with the body in $(Join-Path $OutDir 'deleted-assignments.jsonl')"
if (-not $gone -or -not $exactlyOne) { exit 4 }
