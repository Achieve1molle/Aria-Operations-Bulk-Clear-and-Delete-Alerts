<#
.SYNOPSIS
  Cancels ALL active alerts and deletes ALL canceled alerts in VMware Aria Operations 8.x.

.DESCRIPTION
  - Bypasses TLS certificate validation (self-signed / untrusted root).
  - PowerShell 7+: uses Invoke-RestMethod -SkipCertificateCheck.
  - Windows PowerShell 5.1: uses ServerCertificateValidationCallback.
  - Flow:
      1) POST   /suite-api/api/auth/token/acquire         (get OpsToken)
      2) GET    /suite-api/api/alerts?page=&pageSize=     (list alerts, paged)
      3) POST   /suite-api/api/alerts?action=cancel       (bulk cancel active alerts)
      4) DELETE /suite-api/api/alerts/bulk                (bulk delete canceled alerts)

.NOTES
  "Fail loud" behavior:
    - Token acquisition validates:
        * non-empty response
        * JSON content type (when available)
        * presence of .token
    - If HTML/redirect/login is returned, script throws with a response preview.
    - If JSON error payload returned, throws with the JSON body.

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$AriaOpsFqdnOrIp,

  # Prefer PSCredential so you don't put passwords in command history
  [Parameter(Mandatory=$false)]
  [pscredential]$Credential,

  # If you use AD/LDAP/vIDM auth sources, set this to the Authentication Source name in Aria Ops
  [Parameter(Mandatory=$false)]
  [string]$AuthSource = "LOCAL",

  [Parameter(Mandatory=$false)]
  [int]$PageSize = 1000,

  [Parameter(Mandatory=$false)]
  [int]$CancelBatchSize = 500,

  # Enables extra diagnostic output and richer exceptions
  [Parameter(Mandatory=$false)]
  [switch]$FailLoud
)

# -------------------------------
# Always bypass TLS validation
# -------------------------------
$ErrorActionPreference = 'Stop'

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

if ($PSVersionTable.PSVersion.Major -lt 7) {
  # Windows PowerShell 5.1 (ServicePointManager path)
  try {
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public static class TrustAllCerts {
  public static bool Validate(object sender, X509Certificate cert, X509Chain chain, System.Net.Security.SslPolicyErrors errors) { return true; }
}
"@ -ErrorAction Stop
  } catch {}
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($sender,$cert,$chain,$errors) return $true }
}

# Common Invoke-RestMethod options; PS7 supports -SkipCertificateCheck directly
$irmCommon = @{
  ErrorAction = 'Stop'
}
if ($PSVersionTable.PSVersion.Major -ge 7) {
  $irmCommon.SkipCertificateCheck = $true
}

# -------------------------------
# Credential prompt (if not provided)
# -------------------------------
if (-not $Credential) {
  $Credential = Get-Credential -Message "Enter Aria Operations credentials"
}

$base = "https://$AriaOpsFqdnOrIp"

# -------------------------------
# Helpers
# -------------------------------
function Get-Preview {
  param(
    [Parameter(Mandatory=$true)][AllowNull()][AllowEmptyString()]
    [string]$Text,
    [int]$Max = 500
  )
  if ([string]::IsNullOrEmpty($Text)) { return "<empty>" }
  $len = [Math]::Min($Max, $Text.Length)
  return $Text.Substring(0, $len)
}

function Invoke-AriaRest {
  param(
    [Parameter(Mandatory=$true)][ValidateSet('GET','POST','DELETE','PUT','PATCH')]
    [string]$Method,

    [Parameter(Mandatory=$true)]
    [string]$Uri,

    [hashtable]$Headers,

    [string]$ContentType,

    [object]$Body
  )

  $params = @{
    Method = $Method
    Uri    = $Uri
  }

  if ($Headers)        { $params.Headers     = $Headers }
  if ($ContentType)    { $params.ContentType = $ContentType }
  if ($null -ne $Body) { $params.Body        = $Body }

  return Invoke-RestMethod @params @irmCommon
}

function Invoke-AriaRestRaw {
  <#
    Returns a rich object with:
      - StatusCode (PS7+ when available)
      - ResponseHeaders (PS7+ when available)
      - ContentType (best effort)
      - RawContent (string)
      - Json (parsed object if JSON)
  #>
  param(
    [Parameter(Mandatory=$true)][ValidateSet('GET','POST','DELETE','PUT','PATCH')]
    [string]$Method,

    [Parameter(Mandatory=$true)]
    [string]$Uri,

    [hashtable]$Headers,

    [string]$ContentType,

    [object]$Body,

    [int]$MaximumRedirection = 0
  )

  $result = [ordered]@{
    Uri             = $Uri
    Method          = $Method
    StatusCode      = $null
    ContentType     = $null
    ResponseHeaders = $null
    RawContent      = $null
    Json            = $null
  }

  if ($PSVersionTable.PSVersion.Major -ge 7) {
    $params = @{
      Method               = $Method
      Uri                  = $Uri
      MaximumRedirection   = $MaximumRedirection
      ErrorAction          = 'Stop'
    }
    if ($irmCommon.SkipCertificateCheck) { $params.SkipCertificateCheck = $true }
    if ($Headers)     { $params.Headers     = $Headers }
    if ($ContentType) { $params.ContentType = $ContentType }
    if ($null -ne $Body) { $params.Body = $Body }

    $sc = $null
    $rh = $null

    # Use Invoke-WebRequest to capture raw content + headers reliably
    $resp = Invoke-WebRequest @params -StatusCodeVariable sc -ResponseHeadersVariable rh

    $result.StatusCode      = $sc
    $result.ResponseHeaders = $rh

    try {
      $result.ContentType = $resp.Headers.'Content-Type'
      if (-not $result.ContentType) { $result.ContentType = $resp.ContentType }
    } catch {}

    $result.RawContent = $resp.Content

  } else {
    # Windows PowerShell 5.1 fallback (no StatusCodeVariable/ResponseHeadersVariable)
    $params = @{
      Method      = $Method
      Uri         = $Uri
      ErrorAction = 'Stop'
    }
    if ($Headers)     { $params.Headers     = $Headers }
    if ($ContentType) { $params.ContentType = $ContentType }
    if ($null -ne $Body) { $params.Body = $Body }

    $resp = Invoke-WebRequest @params
    try { $result.ContentType = $resp.Headers.'Content-Type' } catch {}
    $result.RawContent = $resp.Content
  }

  # Attempt JSON parse if it looks like JSON
  if ($result.RawContent) {
    $looksJson = $false
    if ($result.ContentType -and $result.ContentType -match 'application/json') { $looksJson = $true }
    if (-not $looksJson) {
      $trim = $result.RawContent.TrimStart()
      if ($trim.StartsWith('{') -or $trim.StartsWith('[')) { $looksJson = $true }
    }

    if ($looksJson) {
      try { $result.Json = $result.RawContent | ConvertFrom-Json -ErrorAction Stop } catch {}
    }
  }

  [pscustomobject]$result
}

function Throw-TokenFailLoud {
  param(
    [Parameter(Mandatory=$true)][pscustomobject]$Raw
  )

  $status = if ($Raw.StatusCode) { $Raw.StatusCode } else { "<n/a>" }
  $ctype  = if ($Raw.ContentType) { $Raw.ContentType } else { "<unknown>" }

  $preview = Get-Preview -Text $Raw.RawContent -Max 700

  # Common HTML/SSO/login indicators
  $isHtml = $false
  if ($Raw.ContentType -match 'text/html') { $isHtml = $true }
  if ($Raw.RawContent -match '(?is)<html|<title|sso|single\s*sign|login|redirect') { $isHtml = $true }

  if ($Raw.Json) {
    $jsonText = $Raw.Json | ConvertTo-Json -Depth 20
    throw ("Failed to acquire OpsToken. Token missing. " +
           "HTTP Status=$status; Content-Type=$ctype. " +
           "JSON response: $jsonText")
  }

  if ($isHtml) {
    throw ("Failed to acquire OpsToken. API returned HTML/SSO/UI content (likely redirect/load balancer/SSO). " +
           "HTTP Status=$status; Content-Type=$ctype. " +
           "Response preview: $preview")
  }

  throw ("Failed to acquire OpsToken. Non-JSON response or unexpected payload. " +
         "HTTP Status=$status; Content-Type=$ctype. " +
         "Response preview: $preview")
}

# -------------------------------
# 1) Acquire OpsToken (FAIL LOUD)
# -------------------------------
$tokenUri = "$base/suite-api/api/auth/token/acquire"
$tokenBodyJson = @{
  username   = $Credential.UserName
  password   = $Credential.GetNetworkCredential().Password
  authSource = $AuthSource
} | ConvertTo-Json -Depth 5 -Compress

Write-Host "Acquiring token from $tokenUri ..."

# Token call: use RAW so we can inspect headers/status/content
$tokenHeaders = @{
  "Accept"       = "application/json"
  "Content-Type" = "application/json"
}

$rawToken = Invoke-AriaRestRaw -Method POST -Uri $tokenUri -Headers $tokenHeaders -ContentType "application/json" -Body $tokenBodyJson -MaximumRedirection 0

if ($FailLoud) {
  $sc = if ($rawToken.StatusCode) { $rawToken.StatusCode } else { "<n/a>" }
  $ct = if ($rawToken.ContentType) { $rawToken.ContentType } else { "<unknown>" }
  Write-Host "Token call diagnostics: HTTP=$sc  Content-Type=$ct"
  if ($rawToken.ResponseHeaders) {
    $loc = $rawToken.ResponseHeaders.Location
    if ($loc) { Write-Host "Token call redirect Location header: $loc" }
  }
}

# If token response was parsed as JSON, use it; otherwise fail loud
if (-not $rawToken.Json) {
  Throw-TokenFailLoud -Raw $rawToken
}

$tokenResp = $rawToken.Json
$opsToken  = $tokenResp.token

if (-not $opsToken) {
  Throw-TokenFailLoud -Raw $rawToken
}

# Auth header for subsequent API calls
$headers = @{
  "Accept"        = "application/json"
  "Content-Type"  = "application/json"
  "Authorization" = "OpsToken $opsToken"
}

Write-Host "Token acquired successfully."

# -------------------------------
# 2) Get ALL alerts (paged)
# -------------------------------
function Get-AllAlerts {
  param(
    [hashtable]$Headers,
    [string]$Base,
    [int]$PageSize
  )

  $all = New-Object System.Collections.Generic.List[object]
  $page = 0
  $total = $null

  while ($true) {
    # NOTE: use '&' not '&amp;' (copy/paste formatting often breaks this)
    $uri = "$Base/suite-api/api/alerts?page=$page&pageSize=$PageSize"
    Write-Host "Fetching alerts page=$page pageSize=$PageSize ..."
    $resp = Invoke-AriaRest -Method GET -Uri $uri -Headers $Headers

    if ($resp.alerts) {
      foreach ($a in $resp.alerts) { $all.Add($a) }
    }

    if ($null -eq $total -and $resp.pageInfo -and $resp.pageInfo.totalCount -ne $null) {
      $total = [int]$resp.pageInfo.totalCount
      Write-Host "Total alerts reported by API: $total"
    }

    $page++

    if ($null -ne $total) {
      if ($all.Count -ge $total) { break }
    } else {
      if (-not $resp.alerts -or $resp.alerts.Count -eq 0) { break }
    }

    if ($page -gt 2000) { throw "Aborting: exceeded 2000 pages while fetching alerts." }
  }

  return $all
}

$alerts = Get-AllAlerts -Headers $headers -Base $base -PageSize $PageSize

# Filter ACTIVE alerts; response includes "status" and "alertId" fields
$activeIds = @()
foreach ($a in $alerts) {
  $status = "$($a.status)"
  if ($status -and $status.Trim().ToUpper() -eq "ACTIVE") {
    if ($a.alertId) { $activeIds += $a.alertId }
    elseif ($a.id)  { $activeIds += $a.id }  # fallback
  }
}

Write-Host "Found ACTIVE alerts: $($activeIds.Count)"

# -------------------------------
# 3) Bulk CANCEL active alerts (chunked)
# -------------------------------
function Invoke-InBatches {
  param(
    [string[]]$Items,
    [int]$BatchSize,
    [scriptblock]$Action
  )

  if (-not $Items -or $Items.Count -eq 0) { return }

  for ($i = 0; $i -lt $Items.Count; $i += $BatchSize) {
    $end = [Math]::Min($i + $BatchSize - 1, $Items.Count - 1)
    $batch = $Items[$i..$end]
    & $Action $batch ([int]($i / $BatchSize) + 1)
  }
}

$cancelUri = "$base/suite-api/api/alerts?action=cancel"

if ($activeIds.Count -gt 0) {
  Invoke-InBatches -Items $activeIds -BatchSize $CancelBatchSize -Action {
    param($batch, $batchNum)

    $body = @{ uuids = $batch } | ConvertTo-Json -Depth 5
    Write-Host "Canceling batch #$batchNum (count=$($batch.Count)) ..."
    Invoke-AriaRest -Method POST -Uri $cancelUri -Headers $headers -ContentType "application/json" -Body $body | Out-Null
  }
  Write-Host "Cancel requests submitted."
} else {
  Write-Host "No ACTIVE alerts to cancel."
}

# -------------------------------
# 4) Bulk DELETE all CANCELED alerts
# -------------------------------
$deleteUri = "$base/suite-api/api/alerts/bulk"

function Try-BulkDeleteCanceled {
  param([string]$StatusValue)

  $deleteBody = @{
    "alert-query" = @{
      alertStatus = @{
        alertStatus = $StatusValue
      }
    }
  } | ConvertTo-Json -Depth 10

  Write-Host "Deleting canceled alerts where alertStatus='$StatusValue' ..."
  Invoke-AriaRest -Method DELETE -Uri $deleteUri -Headers $headers -ContentType "application/json" -Body $deleteBody | Out-Null
}

try {
  Try-BulkDeleteCanceled -StatusValue "CANCELLED"
  Write-Host "Bulk delete completed (CANCELLED)."
} catch {
  Write-Warning "Bulk delete using 'CANCELLED' failed: $($_.Exception.Message)"
  Write-Warning "Retrying with 'CANCELED' ..."
  Try-BulkDeleteCanceled -StatusValue "CANCELED"
  Write-Host "Bulk delete completed (CANCELED)."
}

Write-Host "Done."