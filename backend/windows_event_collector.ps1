# NexusAI local Windows Security Event Collector
# Reads Event IDs 4624 (successful logon) and 4625 (failed logon) on THIS Windows PC only.
# Run PowerShell as Administrator. Never commit the ingest token to GitHub.

$ErrorActionPreference = 'Stop'
$ApiBase = if ($env:NEXUSAI_API_URL) { $env:NEXUSAI_API_URL.TrimEnd('/') } else { 'https://smartech-ai.onrender.com' }
$IngestToken = $env:NEXUSAI_INGEST_TOKEN
$PollSeconds = 15
$InitialLookbackMinutes = 15

if ([string]::IsNullOrWhiteSpace($IngestToken)) {
    Write-Host 'Missing NEXUSAI_INGEST_TOKEN environment variable.' -ForegroundColor Red
    Write-Host 'Set it in this PowerShell session to the same secret configured in Render.'
    exit 1
}

$stateDirectory = Join-Path $env:LOCALAPPDATA 'NexusAI'
$stateFile = Join-Path $stateDirectory 'collector-state.json'
New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
$lastRecordId = 0L
if (Test-Path $stateFile) {
    try {
        $savedState = Get-Content $stateFile -Raw | ConvertFrom-Json
        $lastRecordId = [long]$savedState.last_record_id
    } catch {
        Write-Host 'Could not read previous collector state; starting with recent events.' -ForegroundColor Yellow
    }
}

Write-Host "NexusAI Windows Event Collector" -ForegroundColor Cyan
Write-Host "API: $ApiBase"
Write-Host "Polling Security Event IDs 4624/4625 every $PollSeconds seconds. Stop with Ctrl+C."
Write-Host 'Only this Windows computer is monitored by this script.' -ForegroundColor Yellow

while ($true) {
    try {
        $since = (Get-Date).AddMinutes(-$InitialLookbackMinutes)
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4624, 4625); StartTime = $since } -MaxEvents 100 -ErrorAction SilentlyContinue | Sort-Object RecordId)
        $batch = @()
        $maxSeen = $lastRecordId

        foreach ($event in $events) {
            $recordId = [long]$event.RecordId
            if ($recordId -le $lastRecordId) { continue }
            if ($recordId -gt $maxSeen) { $maxSeen = $recordId }

            $xml = [xml]$event.ToXml()
            $eventData = @{}
            foreach ($node in $xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) {
                $name = $node.GetAttribute('Name')
                if (-not [string]::IsNullOrWhiteSpace($name)) {
                    $eventData[$name] = $node.InnerText
                }
            }

            $username = [string]$eventData['TargetUserName']
            if ([string]::IsNullOrWhiteSpace($username) -or $username -eq '-') {
                $username = [string]$eventData['SubjectUserName']
            }
            if ([string]::IsNullOrWhiteSpace($username) -or $username -eq '-') { $username = 'Unknown' }

            $sourceIp = [string]$eventData['IpAddress']
            if ([string]::IsNullOrWhiteSpace($sourceIp) -or $sourceIp -eq '-') { $sourceIp = 'N/A' }

            $batch += @{
                event_id = [string]$event.Id
                record_id = [string]$event.RecordId
                source_host = $env:COMPUTERNAME
                timestamp = $event.TimeCreated.ToUniversalTime().ToString('o')
                username = $username
                source_ip = $sourceIp
            }
        }

        if ($batch.Count -gt 0) {
            $payload = @{ events = @($batch) } | ConvertTo-Json -Depth 6
            try {
                $response = Invoke-RestMethod -Uri "$ApiBase/api/ingest/windows-events" `
                    -Method Post `
                    -Headers @{ 'X-NexusAI-Ingest-Token' = $IngestToken } `
                    -ContentType 'application/json' `
                    -Body $payload `
                    -TimeoutSec 20
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] accepted=$($response.accepted), skipped=$($response.skipped), stored=$($response.stored_live_events)"
                $lastRecordId = $maxSeen
                @{ last_record_id = $lastRecordId; updated_at = (Get-Date).ToString('o') } |
                    ConvertTo-Json | Set-Content -Path $stateFile -Encoding UTF8
            } catch {
                Write-Host "Upload failed: $($_.Exception.Message)" -ForegroundColor Red
                if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) {
                    Write-Host 'Check that the token in this PowerShell session exactly matches Render.' -ForegroundColor Yellow
                }
            }
        } else {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] No new 4624/4625 events."
            $lastRecordId = $maxSeen
            @{ last_record_id = $lastRecordId; updated_at = (Get-Date).ToString('o') } |
                ConvertTo-Json | Set-Content -Path $stateFile -Encoding UTF8
        }
    } catch {
        Write-Host "Collector error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host 'Confirm PowerShell is running as Administrator and the Security log is readable.' -ForegroundColor Yellow
    }

    Start-Sleep -Seconds $PollSeconds
}
