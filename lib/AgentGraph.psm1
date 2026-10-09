#Requires -Version 7.2
<#
.SYNOPSIS
  Small Microsoft Graph REST layer for agent-driven admin work, plus the pure helper functions the tools use.

.DESCRIPTION
  REST layer:
    - One request function (Invoke-GraphRest) that honors Retry-After (seconds or HTTP date), with
      exponential backoff when the header is missing. GET retries 429, 503 and 504. Writes retry only 429,
      because a POST or DELETE that came back 503 or 504 may already have been applied; for those the caller
      is told to read the object back before trying again.
    - One paging function (Get-GraphPaged) that always follows @odata.nextLink.
    - The session is READ-ONLY by default. Any POST, PATCH, PUT or DELETE is refused until a caller runs
      Set-GraphRestContext -AllowWrites, which the tools only do behind an explicit -Apply switch. This is an
      accident guard: anything running as me in the same process can flip it. The real limits are my approval
      of production writes before they run, the token's scopes and my directory roles.
    - The bearer token is only ever sent to https://graph.microsoft.com. An absolute URI or nextLink that
      points anywhere else is refused.
    - All HTTP goes through one replaceable transport, so tests run against synthetic responses and never
      reach a real tenant.

  Helpers (pure functions, unit tested in tests/Run-Tests.ps1):
    ConvertTo-ODataLiteral, ConvertFrom-AppRoleAssignmentId, Test-AppRoleDeleteAllowed, Resolve-ExactlyOne,
    Resolve-DeviceRemovalVerdict, Compare-Snapshot, Get-ReadBackMismatch, Get-SessionDeadline,
    Get-NextQueueStep, ConvertTo-SafeFileName, Invoke-UalPagedSearch.
#>

Set-StrictMode -Version Latest

$script:GraphBase = 'https://graph.microsoft.com'
$script:Token = $null
$script:ReadOnly = $true
$script:Transport = $null
$script:Sleeper = { param([double]$Seconds) Start-Sleep -Milliseconds ([int][math]::Ceiling($Seconds * 1000)) }

#region context and transport ---------------------------------------------------------------------

function Set-GraphRestContext {
  <#
  .SYNOPSIS
    Sets the access token for this process. Read-only unless -AllowWrites is passed.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][securestring] $AccessToken,
    [switch] $AllowWrites
  )
  $script:Token = $AccessToken
  $script:ReadOnly = -not $AllowWrites
}

function Get-GraphRestMode {
  [CmdletBinding()]
  param()
  [pscustomobject]@{ HasToken = [bool]$script:Token; ReadOnly = $script:ReadOnly }
}

function Clear-GraphRestContext {
  [CmdletBinding()]
  param()
  $script:Token = $null
  $script:ReadOnly = $true
}

function Set-GraphRestTestHook {
  <#
  .SYNOPSIS
    Test seam. Replaces the HTTP transport and the sleep function.
  .DESCRIPTION
    Transport receives one hashtable: @{ Method; Uri; Headers; Body; ContentType } and must return an object
    with StatusCode (int), Headers (hashtable) and Content (string). Pass $null to restore the defaults.
  #>
  [CmdletBinding()]
  param(
    [scriptblock] $Transport,
    [scriptblock] $Sleeper
  )
  $script:Transport = $Transport
  if ($Sleeper) {
    $script:Sleeper = $Sleeper
  } else {
    $script:Sleeper = { param([double]$Seconds) Start-Sleep -Milliseconds ([int][math]::Ceiling($Seconds * 1000)) }
  }
}

function Invoke-DefaultHttp {
  param([hashtable] $Request)
  if ($env:M365AGENTOPS_OFFLINE -eq '1') {
    throw 'Network calls are disabled in this process (M365AGENTOPS_OFFLINE=1).'
  }
  $p = @{
    Method             = $Request.Method
    Uri                = $Request.Uri
    Headers            = $Request.Headers
    SkipHttpErrorCheck = $true
    ErrorAction        = 'Stop'
  }
  if ($null -ne $Request.Body) {
    $p.Body = $Request.Body
    $p.ContentType = $Request.ContentType
  }
  $r = Invoke-WebRequest @p
  $h = @{}
  foreach ($k in $r.Headers.Keys) { $h[$k] = ($r.Headers[$k] -join ',') }
  [pscustomobject]@{ StatusCode = [int]$r.StatusCode; Headers = $h; Content = [string]$r.Content }
}

function Invoke-Transport {
  param([hashtable] $Request)
  if ($script:Transport) { return (& $script:Transport $Request) }
  Invoke-DefaultHttp -Request $Request
}

#endregion

#region request, retry, paging --------------------------------------------------------------------

function Resolve-GraphUri {
  <#
  .SYNOPSIS
    Turns 'v1.0/users' into an absolute Graph URI and refuses any absolute URI on another host.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string] $Uri)
  if ($Uri -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') {
    if (-not $Uri.StartsWith("$script:GraphBase/", [System.StringComparison]::OrdinalIgnoreCase)) {
      throw "Refusing to send a Graph token to '$Uri'. Only $script:GraphBase/ is allowed."
    }
    return $Uri
  }
  $rel = $Uri.TrimStart('/')
  if ($rel -notmatch '^(v1\.0|beta)/') {
    throw "Relative Graph URIs must start with v1.0/ or beta/. Got '$Uri'."
  }
  "$script:GraphBase/$rel"
}

function Get-RetryDelaySeconds {
  <#
  .SYNOPSIS
    Seconds to wait before retrying. Honors Retry-After (delta seconds or HTTP date); otherwise 2, 4, 8 ... up to 60.
  #>
  [CmdletBinding()]
  param(
    [hashtable] $Headers,
    [int] $Attempt = 0,
    [int] $MaxSeconds = 120
  )
  $ra = $null
  if ($Headers) {
    foreach ($k in $Headers.Keys) { if ($k -ieq 'Retry-After') { $ra = [string]$Headers[$k] } }
  }
  if ($ra) {
    $s = 0
    if ([int]::TryParse($ra.Trim(), [ref]$s)) { return [int][math]::Min([math]::Max($s, 1), $MaxSeconds) }
    $d = [datetimeoffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetimeoffset]::TryParse($ra, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) {
      $sec = [int][math]::Ceiling(($d - [datetimeoffset]::UtcNow).TotalSeconds)
      return [int][math]::Min([math]::Max($sec, 1), $MaxSeconds)
    }
  }
  [int][math]::Min([math]::Pow(2, $Attempt + 1), 60)
}

function New-GraphError {
  param([string]$Method, [string]$Uri, [int]$StatusCode, [string]$Content, [string]$Hint)
  $code = ''
  $msg = ''
  if ($Content) {
    try {
      $j = $Content | ConvertFrom-Json -Depth 20
      if ($j.PSObject.Properties['error']) {
        $e = $j.error
        if ($e -is [string]) { $code = $e } else {
          if ($e.PSObject.Properties['code']) { $code = [string]$e.code }
          if ($e.PSObject.Properties['message']) { $msg = [string]$e.message }
        }
      }
    } catch {
      $msg = ($Content.Substring(0, [math]::Min(300, $Content.Length)))
    }
  }
  $text = "Graph $Method $Uri returned $StatusCode $code $msg".Trim()
  if ($Hint) { $text = "$text. $Hint" }
  $ex = [System.InvalidOperationException]::new($text)
  $ex.Data['StatusCode'] = $StatusCode
  $ex.Data['ErrorCode'] = $code
  $ex
}

function Get-GraphErrorStatus {
  <#
  .SYNOPSIS
    Returns the HTTP status code carried by an error thrown from Invoke-GraphRest, or 0.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)] $ErrorRecord)
  $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
  if ($ex -and $ex.Data -and $ex.Data.Contains('StatusCode')) { return [int]$ex.Data['StatusCode'] }
  0
}

function Invoke-GraphRest {
  <#
  .SYNOPSIS
    One Graph request. GET retries 429, 503 and 504; writes retry 429 only. Writes are refused while the
    session is read-only.
  .EXAMPLE
    Invoke-GraphRest -Uri 'v1.0/organization?$select=id,displayName'
  #>
  [CmdletBinding()]
  param(
    [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')][string] $Method = 'GET',
    [Parameter(Mandatory)][string] $Uri,
    $Body,
    [hashtable] $Headers,
    [int] $MaxRetries = 5,
    [int] $MaxRetryAfterSeconds = 120
  )
  $full = Resolve-GraphUri -Uri $Uri
  if ($Method -ne 'GET' -and $script:ReadOnly) {
    throw "Blocked $Method $full because this session is read-only. Writes need the tool's -Apply switch."
  }
  if (-not $script:Token) {
    throw 'No access token in this process. Run auth/Start-DeviceLogin.ps1 first, then Set-GraphRestContext.'
  }
  $plain = [System.Net.NetworkCredential]::new('', $script:Token).Password
  $h = @{ Authorization = "Bearer $plain"; Accept = 'application/json' }
  if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }
  $json = $null
  if ($null -ne $Body) {
    $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 -Compress }
  }
  # A 429 means the request was not processed, so any method can retry it. A 503 or 504 on a write may arrive
  # after the write already happened (an invitation sent, a method registered, a grant re-created), so a blind
  # retry could duplicate it or fail with 409 and report a write that worked as a failure.
  $retryable = if ($Method -eq 'GET') { @(429, 503, 504) } else { @(429) }
  for ($attempt = 0; ; $attempt++) {
    $req = @{ Method = $Method; Uri = $full; Headers = $h; Body = $json; ContentType = $(if ($null -ne $json) { 'application/json' } else { $null }) }
    $resp = Invoke-Transport -Request $req
    $code = [int]$resp.StatusCode
    if ($code -ge 200 -and $code -lt 300) {
      if ([string]::IsNullOrWhiteSpace([string]$resp.Content)) { return $null }
      return ($resp.Content | ConvertFrom-Json -Depth 50)
    }
    if (($code -in $retryable) -and $attempt -lt $MaxRetries) {
      $hdrs = if ($resp.Headers -is [hashtable]) { $resp.Headers } else { @{} }
      $wait = Get-RetryDelaySeconds -Headers $hdrs -Attempt $attempt -MaxSeconds $MaxRetryAfterSeconds
      Write-Verbose "Graph $code on $Method $full; waiting $wait s (attempt $($attempt + 1) of $MaxRetries)"
      & $script:Sleeper $wait
      continue
    }
    $hint = if ($Method -ne 'GET' -and $code -in 503, 504) { 'Not retried: this write may already have been applied. Read the object back before trying again' } else { '' }
    throw (New-GraphError -Method $Method -Uri $full -StatusCode $code -Content ([string]$resp.Content) -Hint $hint)
  }
}

function Get-GraphPaged {
  <#
  .SYNOPSIS
    GETs a collection and follows every @odata.nextLink. Emits the items; wrap the call in @() for an array.
  .NOTES
    A single page of $top=999 is not "all members". This is the bug that made one of my own checks wrong.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $Uri,
    [hashtable] $Headers,
    [int] $MaxPages = 1000
  )
  $items = [System.Collections.Generic.List[object]]::new()
  $next = $Uri
  $pages = 0
  while ($next) {
    $pages++
    if ($pages -gt $MaxPages) { throw "Stopped after $MaxPages pages of $Uri. Raise -MaxPages if that is expected." }
    $r = Invoke-GraphRest -Method GET -Uri $next -Headers $Headers
    if ($null -eq $r) { break }
    if ($r.PSObject.Properties['value']) {
      foreach ($v in @($r.value)) { $items.Add($v) }
      $next = if ($r.PSObject.Properties['@odata.nextLink']) { [string]$r.'@odata.nextLink' } else { $null }
    } else {
      $items.Add($r)
      $next = $null
    }
  }
  $items.ToArray()
}

#endregion

#region pure helpers ------------------------------------------------------------------------------

function Get-PropValue {
  <# Null-safe property read that works under Set-StrictMode. #>
  param($Object, [string] $Name)
  if ($null -eq $Object) { return $null }
  if ($Object -is [System.Collections.IDictionary]) {
    if ($Object.Contains($Name)) { return $Object[$Name] } else { return $null }
  }
  $p = $Object.PSObject.Properties[$Name]
  if ($p) { return $p.Value }
  $null
}

function ConvertTo-ODataLiteral {
  <#
  .SYNOPSIS
    Makes a value safe to put inside '...' in a $filter: doubles single quotes (OData), then URL-encodes it.
  .DESCRIPTION
    Without the encoding, a guest UPN like partner.user_example.com#EXT#@contoso.onmicrosoft.com cuts the URI
    off at '#' (everything after it becomes a fragment), and '&' or '+' in a name breaks the query string.
  .EXAMPLE
    "v1.0/users?`$filter=userPrincipalName eq '$(ConvertTo-ODataLiteral $upn)'"
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyString()][string] $Value)
  [uri]::EscapeDataString($Value.Replace("'", "''"))
}

function ConvertFrom-AppRoleAssignmentId {
  <#
  .SYNOPSIS
    Decodes the principal object id that an appRoleAssignment id carries in its first 22 base64url characters.
  .NOTES
    Observed behavior, not a documented contract. Use it as a cross-check against principalId, never as the
    only source of truth. Returns $null if the id cannot be decoded.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string] $Id)
  if ($Id.Length -lt 22) { return $null }
  try {
    $b64 = $Id.Substring(0, 22).Replace('-', '+').Replace('_', '/') + '=='
    $bytes = [Convert]::FromBase64String($b64)
    if ($bytes.Length -lt 16) { return $null }
    return [guid]::new([byte[]]$bytes[0..15])
  } catch {
    return $null
  }
}

function ConvertTo-AppRoleAssignmentIdPrefix {
  <# Test helper: the 22-character base64url prefix for a principal GUID. #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][guid] $PrincipalId)
  [Convert]::ToBase64String($PrincipalId.ToByteArray()).Substring(0, 22).Replace('+', '-').Replace('/', '_')
}

function Test-AppRoleDeleteAllowed {
  <#
  .SYNOPSIS
    Decides whether deleting one appRoleAssignment can only affect the named user.
  .DESCRIPTION
    GET /users/{id}/appRoleAssignments also returns grants made to groups the user is a direct member of.
    For those, principalType is 'Group' and principalId is the group. Deleting one removes the app for every
    member of the group. This function refuses unless the grant is a direct user grant to this exact user,
    and the id decodes to the same principal (fail closed if it does not).
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] $Assignment,
    [Parameter(Mandatory)][string] $UserId,
    [switch] $SkipIdDecodeCheck
  )
  $ptype = [string](Get-PropValue $Assignment 'principalType')
  $pid_ = [string](Get-PropValue $Assignment 'principalId')
  $pname = [string](Get-PropValue $Assignment 'principalDisplayName')
  $aid = [string](Get-PropValue $Assignment 'id')
  $decoded = if ($aid) { ConvertFrom-AppRoleAssignmentId -Id $aid } else { $null }
  $result = [ordered]@{
    Allowed            = $false
    Reason             = ''
    PrincipalType      = $ptype
    PrincipalId        = $pid_
    DecodedPrincipalId = if ($decoded) { $decoded.ToString() } else { $null }
  }
  if ($ptype -ne 'User') {
    $result.Reason = "This grant belongs to $ptype '$pname' ($pid_), not to the user. Deleting it removes the app for every member. Remove the user from that $ptype instead, or change the $ptype grant deliberately."
    return [pscustomobject]$result
  }
  if ($pid_ -ne $UserId) {
    $result.Reason = "principalId $pid_ is not the target user $UserId."
    return [pscustomobject]$result
  }
  if (-not $SkipIdDecodeCheck) {
    if (-not $decoded) {
      $result.Reason = 'The assignment id did not decode to a GUID. Refusing (fail closed). Inspect it by hand or pass -SkipIdDecodeCheck.'
      return [pscustomobject]$result
    }
    if ($decoded.ToString() -ne $pid_) {
      $result.Reason = "The assignment id decodes to $decoded, not to principalId $pid_. Refusing."
      return [pscustomobject]$result
    }
  }
  $result.Allowed = $true
  $result.Reason = 'Direct user grant to this user.'
  [pscustomobject]$result
}

function Resolve-ExactlyOne {
  <#
  .SYNOPSIS
    Matches items on one property (case-insensitive exact match). Resolved only when exactly one item matches.
  #>
  [CmdletBinding()]
  param(
    [AllowEmptyCollection()][object[]] $Items = @(),
    [Parameter(Mandatory)][string] $Property,
    [Parameter(Mandatory)][string] $Value
  )
  $m = @($Items | Where-Object { [string](Get-PropValue $_ $Property) -ieq $Value })
  $status = switch ($m.Count) { 0 { 'NotFound' } 1 { 'Resolved' } default { 'Ambiguous' } }
  [pscustomobject]@{
    Status  = $status
    Value   = $Value
    Item    = $(if ($m.Count -eq 1) { $m[0] } else { $null })
    Matches = $m.Count
    Ids     = @($m | ForEach-Object { Get-PropValue $_ 'id' })
  }
}

function ConvertTo-NullableDate {
  param($Value)
  if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
  try {
    $d = [datetimeoffset]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
    if ($d.Year -le 1) { return $null }
    return $d
  } catch { return $null }
}

function Resolve-DeviceRemovalVerdict {
  <#
  .SYNOPSIS
    Concludes, by elimination, why an Intune managed device record is gone.
  .DESCRIPTION
    Evidence is a hashtable:
      Now                         [datetimeoffset]
      AuditWindowStart            [datetimeoffset]  start of the Intune audit events that were searched
      ManagedDevices              current Intune managedDevices matching the serial, name or user
      EntraDevices                Entra device objects (approximateLastSignInDateTime)
      AutopilotIdentities         Autopilot identities (lastContactedDateTime, managedDeviceId)
      CleanupRules                managedDeviceCleanupRules (deviceInactivityBeforeRetirementInDays)
      MatchingAdminRemovalEvents  Intune audit events with Delete, Retire or Wipe that match the device
      FailedSteps                 names of evidence queries that did not return complete data (an HTTP error,
                                  a 403, or the page cap). Any entry here means "not collected", not "empty".
    Verdicts: StillEnrolled, AdminAction, CleanupRuleByElimination, Undetermined.
    A device record that is still there is positive evidence and wins. Otherwise, if any evidence query
    failed, the verdict is Undetermined and names the failed steps: elimination only works on evidence that
    was actually collected.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Evidence)
  $failed = @($Evidence['FailedSteps'] | Where-Object { $_ })
  $now = if ($Evidence['Now']) { [datetimeoffset]$Evidence['Now'] } else { [datetimeoffset]::UtcNow }
  $managed = @($Evidence['ManagedDevices'] | Where-Object { $_ })
  $entra = @($Evidence['EntraDevices'] | Where-Object { $_ })
  $ap = @($Evidence['AutopilotIdentities'] | Where-Object { $_ })
  $rules = @($Evidence['CleanupRules'] | Where-Object { $_ })
  $admin = @($Evidence['MatchingAdminRemovalEvents'] | Where-Object { $_ })
  $windowStart = if ($Evidence['AuditWindowStart']) { [datetimeoffset]$Evidence['AuditWindowStart'] } else { $null }

  $notes = [System.Collections.Generic.List[string]]::new()
  $lastSeen = $null
  foreach ($d in $entra) {
    $t = ConvertTo-NullableDate (Get-PropValue $d 'approximateLastSignInDateTime')
    if ($t -and (-not $lastSeen -or $t -gt $lastSeen)) { $lastSeen = $t }
  }
  foreach ($a in $ap) {
    $t = ConvertTo-NullableDate (Get-PropValue $a 'lastContactedDateTime')
    if ($t -and (-not $lastSeen -or $t -gt $lastSeen)) { $lastSeen = $t }
  }
  $managedIds = @($managed | ForEach-Object { [string](Get-PropValue $_ 'id') })
  foreach ($a in $ap) {
    $mid = [string](Get-PropValue $a 'managedDeviceId')
    if ($mid -and $mid -ne '00000000-0000-0000-0000-000000000000' -and $managedIds -notcontains $mid) {
      $notes.Add("Autopilot identity $(Get-PropValue $a 'serialNumber') still points at managed device $mid, which no longer exists.")
    }
  }
  $days = $null
  foreach ($r in $rules) {
    $v = Get-PropValue $r 'deviceInactivityBeforeRetirementInDays'
    if ($null -ne $v -and [int]$v -gt 0) { if ($null -eq $days -or [int]$v -lt $days) { $days = [int]$v } }
  }

  $verdict = 'Undetermined'
  $summary = ''
  $eligible = $null
  if ($managed.Count -gt 0) {
    $verdict = 'StillEnrolled'
    $summary = "The device still has $($managed.Count) Intune managed device record(s)."
  } elseif ($failed.Count -gt 0) {
    $summary = "Evidence incomplete: $($failed -join '; ') did not return complete data. Nothing can be concluded by elimination until those queries succeed."
  } elseif ($admin.Count -gt 0) {
    $first = $admin | Sort-Object { ConvertTo-NullableDate (Get-PropValue $_ 'activityDateTime') } | Select-Object -First 1
    $actor = Get-PropValue (Get-PropValue $first 'actor') 'userPrincipalName'
    $verdict = 'AdminAction'
    $summary = "Removed by an admin action: '$(Get-PropValue $first 'displayName')' at $(Get-PropValue $first 'activityDateTime') by $actor."
  } elseif ($null -ne $days -and $lastSeen) {
    $eligible = $lastSeen.AddDays($days)
    if ($eligible -gt $now) {
      $summary = "Not yet eligible for the $days-day cleanup rule (eligible from $($eligible.ToString('yyyy-MM-dd'))). Something else removed it."
    } elseif ($windowStart -and $eligible -lt $windowStart) {
      $summary = "Eligible for the $days-day cleanup rule from $($eligible.ToString('yyyy-MM-dd')), but the audit window starts later, so an admin delete cannot be ruled out. Widen -Since."
    } elseif (($entra.Count + $ap.Count) -eq 0) {
      $summary = 'No Entra or Autopilot object remains, which points at a wider cleanup than the Intune rule. Check directoryAudits.'
    } else {
      $verdict = 'CleanupRuleByElimination'
      $summary = "No admin Delete, Retire or Wipe event matches the device in the audit window. Last seen $($lastSeen.ToString('yyyy-MM-dd')); the $days-day inactivity cleanup rule made it eligible from $($eligible.ToString('yyyy-MM-dd')). The Entra and Autopilot objects remain, which fits an Intune-side removal."
    }
  } else {
    $summary = 'No cleanup rule or no last-seen date to reason from. Check the unified audit log.'
  }
  [pscustomobject]@{
    Verdict          = $verdict
    Summary          = $summary
    LastSeen         = $lastSeen
    CleanupRuleDays  = $days
    EligibleFrom     = $eligible
    FailedSteps      = $failed
    Notes            = $notes.ToArray()
  }
}

function ConvertTo-StableJson {
  param($Value)
  if ($null -eq $Value) { return 'null' }
  $Value | ConvertTo-Json -Depth 20 -Compress
}

function Compare-Snapshot {
  <#
  .SYNOPSIS
    Compares named properties of two objects by their JSON form. Emits one row per difference.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] $Before,
    [Parameter(Mandatory)] $After,
    [Parameter(Mandatory)][string[]] $Property
  )
  foreach ($p in $Property) {
    $b = ConvertTo-StableJson (Get-PropValue $Before $p)
    $a = ConvertTo-StableJson (Get-PropValue $After $p)
    if ($b -ne $a) { [pscustomobject]@{ Property = $p; Before = $b; After = $a } }
  }
}

function Get-ReadBackMismatch {
  <#
  .SYNOPSIS
    Compares a value I sent with the value Graph returned, field by field. Returns $null when every field I sent
    came back with the value I sent, otherwise a one-line description of the first difference.
  .DESCRIPTION
    Key order does not matter, and properties the server added on its own (defaults such as operator or
    detectionValue on an Intune detection rule) are not counted as a mismatch. Arrays are compared in order and
    must have the same length. Strings are compared case-sensitively, except GUID-shaped strings (with or
    without braces), which Intune may return in a different case. An empty string and null are treated alike.
  #>
  [CmdletBinding()]
  param([AllowNull()] $Desired, [AllowNull()] $Actual, [string] $Path = 'value')
  $isObj = { param($v) $v -is [System.Collections.IDictionary] -or $v -is [System.Management.Automation.PSCustomObject] }
  $isEmpty = { param($v) $null -eq $v -or ($v -is [string] -and $v -eq '') }
  $show = { param($v) $s = ConvertTo-StableJson $v; if ($s.Length -gt 120) { $s.Substring(0, 117) + '...' } else { $s } }
  if (& $isEmpty $Desired) {
    if (& $isEmpty $Actual) { return $null }
    return "$($Path): sent empty, read back $(& $show $Actual)"
  }
  if (& $isObj $Desired) {
    if (-not (& $isObj $Actual)) { return "$($Path): sent an object, read back $(& $show $Actual)" }
    $keys = if ($Desired -is [System.Collections.IDictionary]) { @($Desired.Keys) } else { @($Desired.PSObject.Properties.Name) }
    foreach ($k in $keys) {
      # Read the values directly: a function that returns a one-item array would unroll it.
      $dv = if ($Desired -is [System.Collections.IDictionary]) { $Desired[$k] } else { $Desired.PSObject.Properties[$k].Value }
      $av = $null
      if ($Actual -is [System.Collections.IDictionary]) { if ($Actual.Contains($k)) { $av = $Actual[$k] } }
      elseif ($Actual.PSObject.Properties[$k]) { $av = $Actual.PSObject.Properties[$k].Value }
      $m = Get-ReadBackMismatch -Desired $dv -Actual $av -Path "$Path.$k"
      if ($m) { return $m }
    }
    return $null
  }
  if ($Desired -is [System.Collections.IList]) {
    # Built explicitly: assigning @() or a one-item array from an if statement would unroll it.
    $a = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $Actual) {
      if ($Actual -is [System.Collections.IList]) { foreach ($x in $Actual) { $a.Add($x) } } else { $a.Add($Actual) }
    }
    if ($Desired.Count -ne $a.Count) { return "$($Path): sent $($Desired.Count) item(s), read back $($a.Count)" }
    for ($i = 0; $i -lt $Desired.Count; $i++) {
      $m = Get-ReadBackMismatch -Desired $Desired[$i] -Actual $a[$i] -Path "$Path[$i]"
      if ($m) { return $m }
    }
    return $null
  }
  $same = $false
  if ($Desired -is [bool]) {
    $same = ($Actual -is [bool] -and $Actual -eq $Desired)
  } elseif ($Desired -is [decimal] -or ($Desired.GetType().IsPrimitive -and $Desired -isnot [char])) {
    try { $same = ([decimal]$Actual -eq [decimal]$Desired) } catch { $same = $false }
  } else {
    $ds = [string]$Desired
    $as = [string]$Actual
    $guid = '^\{?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}?$'
    $same = if ($ds -match $guid -and $as -match $guid) { $ds -ieq $as } else { $ds -ceq $as }
  }
  if ($same) { return $null }
  "$($Path): sent $(& $show $Desired), read back $(& $show $Actual)"
}

function Get-SessionDeadline {
  <#
  .SYNOPSIS
    When a long-running worker must stop: the session limit, or the earliest not-after time of the tokens it
    holds, whichever comes first.
  .DESCRIPTION
    A worker that reuses a cached token must not count its limit from its own start: the token may already be
    most of the way through its life. Not-after times come from Get-AgentAccessToken, which already keeps them
    at least 5 minutes inside the token's real expiry.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][datetimeoffset] $Start,
    [Parameter(Mandatory)][int] $MaxSessionMinutes,
    [object[]] $TokenNotAfter = @()
  )
  $deadline = $Start.AddMinutes($MaxSessionMinutes)
  $reason = "session limit of $MaxSessionMinutes minutes"
  foreach ($t in @($TokenNotAfter | Where-Object { $null -ne $_ })) {
    $na = [datetimeoffset]$t
    if ($na -lt $deadline) { $deadline = $na; $reason = 'earliest token not-after time' }
  }
  [pscustomobject]@{ Deadline = $deadline; Reason = $reason }
}

function Get-NextQueueStep {
  <#
  .SYNOPSIS
    Next NN-name.ps1 in a queue folder that has no .done marker, in name order. Other files are ignored.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string] $QueueDir)
  Get-ChildItem -LiteralPath $QueueDir -File -Filter '*.ps1' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^\d{2}-[A-Za-z0-9_-]+\.ps1$' -and -not (Test-Path -LiteralPath "$($_.FullName).done") } |
    Sort-Object Name |
    Select-Object -First 1
}

function ConvertTo-SafeFileName {
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyString()][string] $Name, [int] $MaxLength = 80)
  $s = ($Name -replace '[^\w\-\.]', '_') -replace '_{2,}', '_'
  $s = $s.Trim('_', '.')
  if (-not $s) { $s = 'unnamed' }
  if ($s.Length -gt $MaxLength) { $s = $s.Substring(0, $MaxLength) }
  $s
}

function Invoke-UalPagedSearch {
  <#
  .SYNOPSIS
    Pages Search-UnifiedAuditLog with one SessionId and SessionCommand ReturnLargeSet until the set is exhausted.
  .DESCRIPTION
    SearchBlock receives the session id and must run Search-UnifiedAuditLog with
    -SessionId $args[0] -SessionCommand ReturnLargeSet -ResultSize 5000 and the same filters every call.
    A single call with ReturnLargeSet returns only the first 5,000 rows; the loop is the point.
    Records are de-duplicated on Identity because ReturnLargeSet results are not sorted.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][scriptblock] $SearchBlock,
    [int] $MaxRecords = 50000,
    [int] $MaxCalls = 20,
    [string] $SessionId = ([guid]::NewGuid().ToString())
  )
  $seen = [System.Collections.Generic.HashSet[string]]::new()
  $out = [System.Collections.Generic.List[object]]::new()
  $total = $null
  for ($call = 1; $call -le $MaxCalls; $call++) {
    $batch = @(& $SearchBlock $SessionId)
    if ($batch.Count -eq 0) { break }
    foreach ($r in $batch) {
      $idx = Get-PropValue $r 'ResultIndex'
      if ($null -ne $idx -and [int]$idx -eq -1) {
        throw 'Search-UnifiedAuditLog returned ResultIndex -1 (service-side failure). Rerun with a narrower date range.'
      }
      $rc = Get-PropValue $r 'ResultCount'
      if ($null -ne $rc) { $total = [int]$rc }
      $key = [string](Get-PropValue $r 'Identity')
      if (-not $key) { $key = [guid]::NewGuid().ToString() }
      if ($seen.Add($key)) { $out.Add($r) }
    }
    if ($null -ne $total -and $out.Count -ge $total) { break }
    if ($out.Count -ge $MaxRecords) { break }
  }
  [pscustomobject]@{ SessionId = $SessionId; ResultCount = $total; Records = $out.ToArray() }
}

#endregion

Export-ModuleMember -Function @(
  'Set-GraphRestContext', 'Get-GraphRestMode', 'Clear-GraphRestContext', 'Set-GraphRestTestHook',
  'Resolve-GraphUri', 'Get-RetryDelaySeconds', 'Get-GraphErrorStatus', 'Invoke-GraphRest', 'Get-GraphPaged',
  'Get-PropValue', 'ConvertTo-ODataLiteral', 'ConvertFrom-AppRoleAssignmentId', 'ConvertTo-AppRoleAssignmentIdPrefix',
  'Test-AppRoleDeleteAllowed', 'Resolve-ExactlyOne', 'Resolve-DeviceRemovalVerdict', 'Compare-Snapshot',
  'Get-ReadBackMismatch', 'Get-SessionDeadline', 'Get-NextQueueStep', 'ConvertTo-SafeFileName', 'Invoke-UalPagedSearch'
)
