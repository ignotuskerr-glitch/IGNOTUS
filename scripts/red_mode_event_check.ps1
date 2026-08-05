param(
    [Parameter(Mandatory = $true)]
    [string]$Marker,
    [Parameter(Mandatory = $true)]
    [string]$StartUtc,
    [int]$TcpPort = 0
)

$ErrorActionPreference = 'SilentlyContinue'
$start = [DateTime]::Parse($StartUtc).ToLocalTime()

function Test-MarkerEvent {
    param([string]$LogName, [int]$EventId, [string]$Signal, [string]$Pattern = $Marker)
    try {
        $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        if (-not $log.IsEnabled) {
            return [pscustomobject]@{ signal = $Signal; log = $LogName; event_id = $EventId; accessible = $true; enabled = $false; observed = $false; record_id = $null }
        }
        $event = Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $EventId; StartTime = $start } -MaxEvents 500 -ErrorAction SilentlyContinue |
            Where-Object { $Pattern -and $_.Message -like "*$Pattern*" } |
            Select-Object -First 1
        return [pscustomobject]@{
            signal = $Signal
            log = $LogName
            event_id = $EventId
            accessible = $true
            enabled = $true
            observed = [bool]$event
            record_id = if ($event) { [long]$event.RecordId } else { $null }
        }
    } catch {
        return [pscustomobject]@{ signal = $Signal; log = $LogName; event_id = $EventId; accessible = $false; enabled = $false; observed = $false; record_id = $null }
    }
}

@(
    Test-MarkerEvent 'Microsoft-Windows-PowerShell/Operational' 4104 'powershell_script_block'
    Test-MarkerEvent 'Microsoft-Windows-PowerShell/Operational' 4103 'powershell_module'
    Test-MarkerEvent 'Security' 4688 'security_process_create'
    Test-MarkerEvent 'Microsoft-Windows-Sysmon/Operational' 1 'sysmon_process_create'
    Test-MarkerEvent 'Microsoft-Windows-Sysmon/Operational' 3 'sysmon_network_connect' $(if ($TcpPort -gt 0) { [string]$TcpPort } else { '' })
    Test-MarkerEvent 'Microsoft-Windows-Sysmon/Operational' 11 'sysmon_file_create'
    Test-MarkerEvent 'Microsoft-Windows-Sysmon/Operational' 12 'sysmon_registry_create_delete'
    Test-MarkerEvent 'Microsoft-Windows-Sysmon/Operational' 13 'sysmon_registry_value_set'
    Test-MarkerEvent 'Microsoft-Windows-Sysmon/Operational' 17 'sysmon_pipe_create'
    Test-MarkerEvent 'Microsoft-Windows-Sysmon/Operational' 18 'sysmon_pipe_connect'
) | ConvertTo-Json -Depth 5 -Compress
