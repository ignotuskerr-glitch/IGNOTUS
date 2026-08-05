param(
    [Parameter(Mandatory = $true)]
    [string]$Marker,
    [Parameter(Mandatory = $true)]
    [string]$StartUtc
)

$ErrorActionPreference = 'SilentlyContinue'
$start = [DateTime]::Parse($StartUtc).ToLocalTime().AddMinutes(-1)
$logName = 'Microsoft-Windows-Windows Defender/Operational'
$eventsAccessible = $false
$events = @()

try {
    $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
    $eventsAccessible = [bool]$log.IsEnabled
    if ($eventsAccessible) {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = $logName
            Id = @(1116, 1117, 1118, 1119)
            StartTime = $start
        } -MaxEvents 200 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -like "*$Marker*" } |
        ForEach-Object {
            $messageBytes = [Text.Encoding]::UTF8.GetBytes([string]$_.Message)
            $sha = [Security.Cryptography.SHA256]::Create()
            $messageHash = ([BitConverter]::ToString($sha.ComputeHash($messageBytes))).Replace('-', '')
            [pscustomobject]@{
                id = [int]$_.Id
                record_id = [long]$_.RecordId
                time_created = $_.TimeCreated.ToUniversalTime().ToString('o')
                message_sha256 = $messageHash
            }
        })
    }
} catch { $eventsAccessible = $false }

$threatsAccessible = $false
$threats = @()
try {
    $threatsAccessible = $true
    $threats = @(Get-MpThreatDetection -ErrorAction Stop |
        Where-Object {
            $_.InitialDetectionTime -ge $start -and
            ((@($_.Resources) -join ' ') -like "*$Marker*")
        } |
        ForEach-Object {
            [pscustomobject]@{
                threat_id = [long]$_.ThreatID
                threat_name = [string]$_.ThreatName
                action_success = [bool]$_.ActionSuccess
                status_id = [int]$_.ThreatStatusID
                execution_status_id = [int]$_.CurrentThreatExecutionStatusID
                initial_detection_time = $_.InitialDetectionTime.ToUniversalTime().ToString('o')
                resources = @($_.Resources)
            }
        })
} catch { $threatsAccessible = $false }

[pscustomobject]@{
    event_log_accessible = $eventsAccessible
    threat_history_accessible = $threatsAccessible
    events = $events
    threats = $threats
} | ConvertTo-Json -Depth 8 -Compress
