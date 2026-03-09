<#
.SYNOPSIS
  Cancel a limited number of ACTIVE alerts (oldest by startTimeUTC) and optionally delete CANCELLED alerts,
  with checkpoint/resume support.

.DESCRIPTION
  Features:
    - Fail-loud token acquisition
    - TLS cert bypass (PS7 uses SkipCertificateCheck; PS5.1 uses callback)
    - TimeoutSec on all API calls
    - Retry with backoff on transient failures
    - Select oldest ACTIVE alerts by startTimeUTC (client-side sort)
    - Limit to MaxActiveToCancel per run (e.g. 50k)
    - Cancel in batches
    - Optional bulk delete CANCELLED alerts
    - Checkpoint file captures progress and supports -Resume

.Execute Example

First run (cancel oldest 50k active)
  .\Clear-AriaOps-Alerts-Limited-Checkpoint.ps1 `
  -AriaOpsFqdnOrIp exampleserver.domain.com `
  -PageSize 200 `
  -MaxActiveToCancel 50000 `
  -DeleteCanceledAfterCancel `
  -TimeoutSec 600 `
  -MaxRetries 5 `
  -RetryBackoffSec 10

Resume after interruption (power loss / timeout / manual stop)
  .\Clear-AriaOps-Alerts-Limited-Checkpoint.ps1 `
  -AriaOpsFqdnOrIp <fqdn> `
  -MaxActiveToCancel 50000 `
  -DeleteCanceledAfterCancel `
  -Resume


.NOTES
  Checkpoint Phases:
    SELECT -> CANCEL -> DELETE(optional) -> DONE
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$AriaOpsFqdnOrIp,

  [Parameter(Mandatory=$false)]
  [pscredential]$Credential,

  [Parameter(Mandatory=$false)]
  [string]$AuthSource = "LOCAL",

  [Parameter(Mandatory=$false)]
  [ValidateRange(50,5000)]
  [int]$PageSize = 200,

  [Parameter(Mandatory=$false)]
  [ValidateRange(10,2000)]
  [int]$CancelBatchSize = 500,

  [Parameter(Mandatory=$false)]
  [ValidateRange(1,500000)]
  [int]$MaxActiveToCancel = 50000,

  [Parameter(Mandatory=$false)]
  [ValidateRange(30,3600)]
  [int]$TimeoutSec = 600,

  [Parameter(Mandatory=$false)]
  [ValidateRange(0,20)]
  [int]$MaxRetries = 5,

  [Parameter(Mandatory=$false)]
  [ValidateRange(1,300)]
  [int]$RetryBackoffSec = 10,

  [Parameter(Mandatory=$false)]
  [switch]$DeleteCanceledAfterCancel,

  # ---- Checkpoint controls ----
  [Parameter(Mandatory=$false)]
  [string]$CheckpointPath = ".\ariaops-alert-cleanup.checkpoint.json",

  [Parameter(Mandatory=$false)]
  [switch]$Resume,

  [Parameter(Mandatory=$false)]
  [switch]$ForceResume,

  [Parameter(Mandatory=$false)]
  [ValidateRange(1,500)]
  [int]$CheckpointEveryPages = 5,

  [Parameter(Mandatory=$false)]
  [switch]$RemoveCheckpointOnSuccess,

  # Extra diagnostics
  [Parameter(Mandatory=$false)]
  [switch]$FailLoud
)

# -------------------------------
# TLS / Cert bypass
# -------------------------------
$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

if ($PSVersionTable.PSVersion.Major -lt 7) {
  try {
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public static class TrustAllCerts {
  public static bool Validate(object sender, X509Certificate cert, X509Chain chain, System.Net.Security.SslPolicyErrors errors) { return true; }
}
"@ -ErrorAction Stop
  } catch {}
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

$irmCommon = @{
  ErrorAction = 'Stop'
  TimeoutSec  = $TimeoutSec
}
if ($PSVersionTable.PSVersion.Major -ge 7) { $irmCommon.SkipCertificateCheck = $true }

if (-not $Credential) {
  $Credential = Get-Credential -Message "Enter Aria Operations credentials"
}

$base = "https://$AriaOpsFqdnOrIp"

# -------------------------------
# Helpers
# -------------------------------
function Invoke-WithRetry {
  param(
    [scriptblock]$Script,
    [string]$Operation = "API call"
  )

  $attempts = [Math]::Max(1, $MaxRetries)
  for ($attempt = 1; $attempt -le $attempts; $attempt++) {
    try {
      return & $Script
    } catch {
      if ($attempt -eq $attempts) { throw }
      $sleep = $RetryBackoffSec * $attempt
      Write-Warning "$Operation failed (attempt $attempt/$attempts). Sleeping $sleep sec. Error: $($_.Exception.Message)"
      Start-Sleep -Seconds $sleep
    }
  }
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

  $params = @{ Method = $Method; Uri = $Uri }
  if ($Headers)     { $params.Headers = $Headers }
  if ($ContentType) { $params.ContentType = $ContentType }
  if ($null -ne $Body) { $params.Body = $Body }

  Invoke-RestMethod @params @irmCommon
}

function Invoke-AriaRestRaw {
  # Version-safe wrapper around Invoke-WebRequest to capture raw token failures.
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

  $cmd = Get-Command Invoke-WebRequest -ErrorAction Stop
  $params = @{ Method = $Method; Uri = $Uri; ErrorAction = 'Stop' }

  if ($cmd.Parameters.ContainsKey('MaximumRedirection')) { $params.MaximumRedirection = $MaximumRedirection }
  if ($cmd.Parameters.ContainsKey('TimeoutSec'))         { $params.TimeoutSec = $TimeoutSec }
  if ($Headers)     { $params.Headers = $Headers }
  if ($ContentType) { $params.ContentType = $ContentType }
  if ($null -ne $Body) { $params.Body = $Body }
  if ($cmd.Parameters.ContainsKey('SkipCertificateCheck') -and ($PSVersionTable.PSVersion.Major -ge 7)) { $params.SkipCertificateCheck = $true }
  if ($cmd.Parameters.ContainsKey('SkipHttpErrorCheck')) { $params.SkipHttpErrorCheck = $true }

  try {
    $resp = Invoke-WebRequest @params
    try { $result.StatusCode = [int]$resp.StatusCode } catch {}
    try { $result.ResponseHeaders = $resp.Headers } catch {}
    try { $result.ContentType = $resp.Headers.'Content-Type' } catch {}
    if (-not $result.ContentType) { try { $result.ContentType = $resp.ContentType } catch {} }
    try { $result.RawContent = $resp.Content } catch {}
  } catch {
    $ex = $_.Exception
    if ($ex.PSObject.Properties.Name -contains 'Response' -and $ex.Response) {
      # PS7 style
      $httpResp = $ex.Response
      try { $result.StatusCode = [int]$httpResp.StatusCode } catch {}
      try { $result.ResponseHeaders = $httpResp.Headers } catch {}
      try {
        if ($httpResp.Content -and $httpResp.Content.Headers -and $httpResp.Content.Headers.ContentType) {
          $result.ContentType = $httpResp.Content.Headers.ContentType.ToString()
        }
      } catch {}
      try {
        if ($httpResp.Content) {
          $result.RawContent = $httpResp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        }
      } catch {}
    } else {
      # PS5.1 style
      $webResp = $null
      try { $webResp = $ex.Response } catch {}

      if ($webResp) {
        try { $result.StatusCode = [int]$webResp.StatusCode } catch {}
        try { $result.ResponseHeaders = $webResp.Headers } catch {}
        try { $result.ContentType = $webResp.ContentType } catch {}
        try {
          $stream = $webResp.GetResponseStream()
          if ($stream) {
            $reader = New-Object System.IO.StreamReader($stream)
            $result.RawContent = $reader.ReadToEnd()
            $reader.Close()
          }
        } catch {}
      }

      if (-not $result.RawContent) { $result.RawContent = $ex.Message }
    }
  }

  # Parse JSON best effort
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
  param([pscustomobject]$Raw)

  $status = if ($Raw.StatusCode) { $Raw.StatusCode } else { "<n/a>" }
  $ctype  = if ($Raw.ContentType) { $Raw.ContentType } else { "<unknown>" }

  $loc = $null
  if ($Raw.ResponseHeaders) {
    try { $loc = $Raw.ResponseHeaders.Location } catch {}
    if (-not $loc) { try { $loc = $Raw.ResponseHeaders['Location'] } catch {} }
  }

  $preview = if ($Raw.RawContent) { $Raw.RawContent.Substring(0, [Math]::Min(900, $Raw.RawContent.Length)) } else { "<empty>" }

  if ($Raw.Json) {
    throw "Failed to acquire OpsToken. HTTP=$status Content-Type=$ctype Location=$loc. JSON: $($Raw.Json | ConvertTo-Json -Depth 20)"
  }

  $isHtml = $false
  if ($Raw.ContentType -match 'text/html') { $isHtml = $true }
  if ($Raw.RawContent -match '(?is)<html|<title|sso|login|redirect|saml') { $isHtml = $true }

  if ($isHtml) {
    throw "Failed to acquire OpsToken. HTTP=$status Content-Type=$ctype Location=$loc. Returned HTML/SSO/UI content. Preview: $preview"
  }

  throw "Failed to acquire OpsToken. HTTP=$status Content-Type=$ctype Location=$loc. Unexpected response. Preview: $preview"
}

# -------------------------------
# Checkpoint helpers
# -------------------------------
function Save-Checkpoint {
  param([hashtable]$State)

  $State.updatedUtc = (Get-Date).ToUniversalTime().ToString("o")
  $json = $State | ConvertTo-Json -Depth 30
  $tmp = "$CheckpointPath.tmp"
  Set-Content -Path $tmp -Value $json -Encoding UTF8
  Move-Item -Path $tmp -Destination $CheckpointPath -Force
}

function Load-Checkpoint {
  if (-not (Test-Path -Path $CheckpointPath)) { return $null }
  try {
    return (Get-Content -Path $CheckpointPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop)
  } catch {
    throw "Checkpoint exists but is unreadable: $CheckpointPath. Error: $($_.Exception.Message)"
  }
}

function Validate-Checkpoint {
  param([object]$Ckpt)
  if (-not $Ckpt) { return }

  $expected = @{
    ariaOps          = $AriaOpsFqdnOrIp
    authSource       = $AuthSource
    pageSize         = $PageSize
    maxActiveToCancel= $MaxActiveToCancel
  }

  $mismatch = @()
  foreach ($k in $expected.Keys) {
    $ck = $Ckpt.$k
    if ($null -ne $ck -and "$ck" -ne "$($expected[$k])") {
      $mismatch += "$k (checkpoint=$ck, current=$($expected[$k]))"
    }
  }

  if ($mismatch.Count -gt 0 -and -not $ForceResume) {
    throw "Checkpoint does not match current parameters: $($mismatch -join '; '). Use -ForceResume to override."
  }
  if ($mismatch.Count -gt 0 -and $ForceResume) {
    Write-Warning "Forcing resume despite mismatch: $($mismatch -join '; ')"
  }
}

# -------------------------------
# 1) Acquire token
# -------------------------------
$tokenUri = "$base/suite-api/api/auth/token/acquire"
$tokenBodyJson = @{
  username   = $Credential.UserName
  password   = $Credential.GetNetworkCredential().Password
  authSource = $AuthSource
} | ConvertTo-Json -Depth 5 -Compress

Write-Host "Acquiring token from $tokenUri ..."
$tokenHeaders = @{ "Accept"="application/json"; "Content-Type"="application/json" }

$rawToken = Invoke-WithRetry -Operation "Token acquire" -Script {
  Invoke-AriaRestRaw -Method POST -Uri $tokenUri -Headers $tokenHeaders -ContentType "application/json" -Body $tokenBodyJson -MaximumRedirection 0
}

if ($FailLoud) {
  $sc = if ($rawToken.StatusCode) { $rawToken.StatusCode } else { "<n/a>" }
  $ct = if ($rawToken.ContentType) { $rawToken.ContentType } else { "<unknown>" }
  Write-Host "Token diagnostics: HTTP=$sc Content-Type=$ct"
}

if (-not $rawToken.Json -or -not $rawToken.Json.token) {
  Throw-TokenFailLoud -Raw $rawToken
}

$opsToken = $rawToken.Json.token

$headers = @{
  "Accept"        = "application/json"
  "Content-Type"  = "application/json"
  "Authorization" = "OpsToken $opsToken"
}

Write-Host "Token acquired successfully."

# -------------------------------
# Initialize/Resume checkpoint state
# -------------------------------
$ckpt = $null

if ($Resume) {
  $ckpt = Load-Checkpoint
  if (-not $ckpt) {
    Write-Warning "Resume requested but checkpoint not found at: $CheckpointPath. Starting fresh."
  } else {
    Validate-Checkpoint -Ckpt $ckpt
    Write-Host "Resuming from checkpoint: $CheckpointPath (phase=$($ckpt.phase))"
  }
}

if (-not $ckpt) {
  $ckpt = [ordered]@{
    version          = 1
    ariaOps          = $AriaOpsFqdnOrIp
    authSource       = $AuthSource
    pageSize         = $PageSize
    maxActiveToCancel= $MaxActiveToCancel
    phase            = "SELECT"
    totalCount       = $null
    lastPage         = $null
    nextPageToFetch  = $null
    pagesFetched     = 0
    candidates       = @()
    selectedIds      = @()
    cancelNextIndex  = 0
    deleteCompleted  = $false
    createdUtc       = (Get-Date).ToUniversalTime().ToString("o")
    updatedUtc       = (Get-Date).ToUniversalTime().ToString("o")
  }
  Save-Checkpoint -State $ckpt
  Write-Host "Created new checkpoint: $CheckpointPath"
}

# -------------------------------
# 2) SELECT phase: find oldest ACTIVE by startTimeUTC (limit N)
# -------------------------------
if ($ckpt.phase -eq "SELECT") {

  if (-not $ckpt.totalCount -or -not $ckpt.lastPage -or $ckpt.nextPageToFetch -eq $null) {
    $firstUri = "$base/suite-api/api/alerts?page=0&pageSize=$PageSize"
    Write-Host "Fetching alerts page=0 pageSize=$PageSize (for totalCount) ..."

    $firstResp = Invoke-WithRetry -Operation "GET alerts page=0" -Script {
      Invoke-AriaRest -Method GET -Uri $firstUri -Headers $headers
    }

    if ($firstResp.pageInfo -and $firstResp.pageInfo.totalCount -ne $null) {
      $ckpt.totalCount = [int]$firstResp.pageInfo.totalCount
      $ckpt.lastPage = [Math]::Ceiling($ckpt.totalCount / [double]$PageSize) - 1
      $ckpt.nextPageToFetch = [int]$ckpt.lastPage
      Write-Host "Total alerts reported by API: $($ckpt.totalCount); lastPage=$($ckpt.lastPage)"
    } else {
      $ckpt.totalCount = $null
      $ckpt.lastPage = 2000
      $ckpt.nextPageToFetch = 2000
      Write-Warning "API did not return totalCount; using fallback lastPage=2000."
    }

    Save-Checkpoint -State $ckpt
  }

  $targetCandidates = [Math]::Ceiling($MaxActiveToCancel * 1.25)

  $cand = New-Object System.Collections.Generic.List[object]
  if ($ckpt.candidates -and $ckpt.candidates.Count -gt 0) {
    foreach ($x in $ckpt.candidates) {
      $cand.Add([pscustomobject]@{ id = [string]$x.id; startTimeUTC = [long]$x.startTimeUTC })
    }
  }

  Write-Host "SELECT phase: collecting ACTIVE candidates from oldest end. TargetCandidates=$targetCandidates."
  Write-Host "Resuming at page=$($ckpt.nextPageToFetch). PagesFetchedSoFar=$($ckpt.pagesFetched)."

  $pagesSinceSave = 0

  while ($ckpt.nextPageToFetch -ge 0 -and $cand.Count -lt $targetCandidates) {
    $p = [int]$ckpt.nextPageToFetch
    $uri = "$base/suite-api/api/alerts?page=$p&pageSize=$PageSize"
    Write-Host "Fetching alerts page=$p pageSize=$PageSize ..."

    $resp = Invoke-WithRetry -Operation "GET alerts page=$p" -Script {
      Invoke-AriaRest -Method GET -Uri $uri -Headers $headers
    }

    if ($resp.alerts) {
      foreach ($a in $resp.alerts) {
        $status = "$($a.status)".Trim().ToUpper()
        if ($status -ne "ACTIVE") { continue }

        $id = $null
        if ($a.alertId) { $id = [string]$a.alertId }
        elseif ($a.id)  { $id = [string]$a.id }
        if (-not $id) { continue }

        $st = $null
        try { $st = [long]$a.startTimeUTC } catch { $st = $null }
        if ($null -eq $st) { $st = [long]::MaxValue }

        $cand.Add([pscustomobject]@{ id = $id; startTimeUTC = $st })
      }
    }

    $ckpt.pagesFetched = [int]$ckpt.pagesFetched + 1
    $ckpt.nextPageToFetch = $p - 1
    $pagesSinceSave++

    if ($pagesSinceSave -ge $CheckpointEveryPages) {
      $ckpt.candidates = @($cand | Select-Object -Property id, startTimeUTC)
      Save-Checkpoint -State $ckpt
      $pagesSinceSave = 0
      Write-Host "Checkpoint saved (SELECT): pagesFetched=$($ckpt.pagesFetched), candidates=$($cand.Count), nextPage=$($ckpt.nextPageToFetch)"
    }
  }

  $ckpt.candidates = @($cand | Select-Object -Property id, startTimeUTC)
  Save-Checkpoint -State $ckpt

  if ($cand.Count -eq 0) {
    Write-Host "No ACTIVE alert candidates found. Marking DONE."
    $ckpt.phase = "DONE"
    $ckpt.selectedIds = @()
    $ckpt.candidates = @()
    Save-Checkpoint -State $ckpt
    return
  }

  $selected = $cand | Sort-Object -Property startTimeUTC, id | Select-Object -First $MaxActiveToCancel

  $ckpt.selectedIds = @($selected.id)
  $ckpt.cancelNextIndex = 0
  $ckpt.phase = "CANCEL"

  $ckpt.candidates = @()
  Save-Checkpoint -State $ckpt

  Write-Host "SELECT complete. Selected ACTIVE alerts to cancel: $($ckpt.selectedIds.Count). Moving to CANCEL phase."
}

# -------------------------------
# 3) CANCEL phase: cancel selected IDs in batches with checkpointed progress
# -------------------------------
if ($ckpt.phase -eq "CANCEL") {

  $ids = @($ckpt.selectedIds)
  if (-not $ids -or $ids.Count -eq 0) {
    Write-Host "CANCEL phase: no selected IDs in checkpoint. Marking DONE."
    $ckpt.phase = "DONE"
    Save-Checkpoint -State $ckpt
    return
  }

  $cancelUri = "$base/suite-api/api/alerts?action=cancel"
  Write-Host "CANCEL phase: total=$($ids.Count), nextIndex=$($ckpt.cancelNextIndex), batchSize=$CancelBatchSize"

  while ($ckpt.cancelNextIndex -lt $ids.Count) {

    $start = [int]$ckpt.cancelNextIndex
    $end   = [Math]::Min($start + $CancelBatchSize - 1, $ids.Count - 1)

    $batch = $ids[$start..$end]
    $batchNum = [Math]::Floor($start / $CancelBatchSize) + 1

    $body = @{ uuids = $batch } | ConvertTo-Json -Depth 5

    Write-Host "Canceling batch #$batchNum (index $start-$end, count=$($batch.Count)) ..."

    Invoke-WithRetry -Operation "POST cancel batch #$batchNum" -Script {
      Invoke-AriaRest -Method POST -Uri $cancelUri -Headers $headers -ContentType "application/json" -Body $body | Out-Null
    }

    $ckpt.cancelNextIndex = $end + 1
    Save-Checkpoint -State $ckpt
    Write-Host "Checkpoint saved (CANCEL): nextIndex=$($ckpt.cancelNextIndex)"
  }

  Write-Host "CANCEL complete."
  $ckpt.phase = $(if ($DeleteCanceledAfterCancel) { "DELETE" } else { "DONE" })
  Save-Checkpoint -State $ckpt
}

# -------------------------------
# 4) DELETE phase (optional): bulk delete CANCELLED alerts
# -------------------------------
if ($ckpt.phase -eq "DELETE") {

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

    Write-Host "Deleting alerts where alertStatus='$StatusValue' ..."
    Invoke-WithRetry -Operation "DELETE alerts/bulk ($StatusValue)" -Script {
      Invoke-AriaRest -Method DELETE -Uri $deleteUri -Headers $headers -ContentType "application/json" -Body $deleteBody | Out-Null
    }
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

  $ckpt.deleteCompleted = $true
  $ckpt.phase = "DONE"
  Save-Checkpoint -State $ckpt
}

# -------------------------------
# DONE phase
# -------------------------------
if ($ckpt.phase -eq "DONE") {
  Write-Host "DONE. Run completed successfully."

  if ($RemoveCheckpointOnSuccess -and (Test-Path $CheckpointPath)) {
    Remove-Item -Path $CheckpointPath -Force
    Write-Host "Checkpoint removed: $CheckpointPath"
  } else {
    Write-Host "Checkpoint retained at: $CheckpointPath"
  }
}
