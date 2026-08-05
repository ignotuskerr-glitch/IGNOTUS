$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

function Get-RegistryValue {
    param([string]$Path, [string]$Name, $Default = $null)
    try {
        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        $value = $item.$Name
        if ($null -eq $value) { return $Default }
        return $value
    } catch { return $Default }
}

function Get-RunKeyEntries {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $item = Get-ItemProperty -LiteralPath $Path
    return @($item.PSObject.Properties |
        Where-Object { $_.Name -notlike 'PS*' } |
        ForEach-Object {
            $command = [Environment]::ExpandEnvironmentVariables([string]$_.Value)
            $target = $null
            if ($command -match '^\s*"([^"]+\.exe)"') { $target = $Matches[1] }
            elseif ($command -match '^\s*([^\s]+\.exe)') { $target = $Matches[1] }
            $signature = $null
            $signer = $null
            if ($target -and (Test-Path -LiteralPath $target)) {
                $trust = Get-AuthenticodeSignature -LiteralPath $target
                $signature = [string]$trust.Status
                $signer = [string]$trust.SignerCertificate.Subject
            }
            [pscustomobject]@{
                path = $Path
                name = $_.Name
                command = $command
                target = $target
                signature = $signature
                signer = $signer
            }
        })
}

function Get-EventLogState {
    param([string]$Name)
    $channelPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$Name"
    $classicPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\$Name"
    $knownToWindows = (Test-Path -LiteralPath $channelPath) -or (Test-Path -LiteralPath $classicPath)
    try {
        $log = Get-WinEvent -ListLog $Name -ErrorAction Stop
        return [pscustomobject]@{
            name = $Name
            exists = $true
            accessible = $true
            enabled = [bool]$log.IsEnabled
            record_count = [long]$log.RecordCount
            maximum_size_bytes = [long]$log.MaximumSizeInBytes
            retention = [bool]$log.LogMode.ToString().Contains('Retain')
            last_write_time = $(if ($log.LastWriteTime) { $log.LastWriteTime.ToUniversalTime().ToString('o') } else { $null })
        }
    } catch {
        return [pscustomobject]@{
            name = $Name
            exists = [bool]$knownToWindows
            accessible = $false
            enabled = $null
            record_count = $null
            maximum_size_bytes = $null
            retention = $null
            last_write_time = $null
            error = $_.Exception.Message
        }
    }
}

$mpStatus = Get-MpComputerStatus
$mpPreference = Get-MpPreference
$providersPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AMSI\Providers'
$providers = if (Test-Path $providersPath) { @(Get-ChildItem $providersPath | ForEach-Object { $_.PSChildName }) } else { @() }

$scriptBlockPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$moduleLogPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
$transcriptionPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'

$eventLogs = @(
    Get-EventLogState 'Microsoft-Windows-PowerShell/Operational'
    Get-EventLogState 'Microsoft-Windows-Windows Defender/Operational'
    Get-EventLogState 'Microsoft-Windows-Sysmon/Operational'
    Get-EventLogState 'Security'
    Get-EventLogState 'System'
)

$deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'
$secureBoot = $null
try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $secureBoot = $null }
$tpm = Get-Tpm

$firewall = @(Get-NetFirewallProfile | ForEach-Object {
    [pscustomobject]@{
        name = $_.Name
        enabled = [bool]$_.Enabled
        default_inbound = [string]$_.DefaultInboundAction
        default_outbound = [string]$_.DefaultOutboundAction
        logging_allowed = [bool]$_.LogAllowed
        logging_blocked = [bool]$_.LogBlocked
        log_max_size_kb = [int]$_.LogMaxSizeKilobytes
    }
})

$sysmonServices = @(Get-CimInstance Win32_Service |
    Where-Object { $_.Name -match '^Sysmon(64)?$' } |
    ForEach-Object {
        [pscustomobject]@{
            name = $_.Name
            state = $_.State
            start_mode = $_.StartMode
            path = $_.PathName
        }
    })

$appLocker = @()
try {
    $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
    $appLocker = @($policy.RuleCollections | ForEach-Object {
        [pscustomobject]@{ type = [string]$_.CollectionType; enforcement = [string]$_.EnforcementMode; rules = @($_).Count }
    })
} catch { $appLocker = @() }

$nonMicrosoftTasks = @()
try {
    $nonMicrosoftTasks = @(Get-ScheduledTask |
        Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
        Select-Object -First 200 |
        ForEach-Object {
            [pscustomobject]@{
                path = "$($_.TaskPath)$($_.TaskName)"
                state = [string]$_.State
                user = [string]$_.Principal.UserId
                run_level = [string]$_.Principal.RunLevel
                actions = @($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() })
            }
        })
} catch { $nonMicrosoftTasks = @() }

$autoServicesNotRunning = @(Get-CimInstance Win32_Service |
    Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' } |
    Select-Object -First 200 |
    ForEach-Object {
        [pscustomobject]@{ name = $_.Name; state = $_.State; account = $_.StartName; path = $_.PathName }
    })

$wmiFilters = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' |
    Select-Object Name,Query,EventNamespace)
$wmiConsumers = @(
    @(Get-CimInstance -Namespace 'root\subscription' -ClassName 'CommandLineEventConsumer' |
        Select-Object Name,CommandLineTemplate,ExecutablePath)
    @(Get-CimInstance -Namespace 'root\subscription' -ClassName 'ActiveScriptEventConsumer' |
        Select-Object Name,ScriptingEngine,ScriptFileName)
)
$wmiBindings = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' |
    ForEach-Object { [pscustomobject]@{ filter = [string]$_.Filter; consumer = [string]$_.Consumer } })

$runKeys = @(
    Get-RunKeyEntries 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
    Get-RunKeyEntries 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    Get-RunKeyEntries 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
    Get-RunKeyEntries 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)

$startupEntries = @()
$startupFolders = @(
    [Environment]::GetFolderPath('Startup'),
    [Environment]::GetFolderPath('CommonStartup')
)
foreach ($folder in $startupFolders) {
    if ($folder -and (Test-Path -LiteralPath $folder)) {
        $startupEntries += @(Get-ChildItem -LiteralPath $folder -Force |
          Where-Object { $_.Name -ne 'desktop.ini' } |
          ForEach-Object {
            $target = $_.FullName
            if ($_.Extension -eq '.lnk') {
                try {
                    $shell = New-Object -ComObject WScript.Shell
                    $target = $shell.CreateShortcut($_.FullName).TargetPath
                } catch { $target = $_.FullName }
            }
            $trust = if ($target -and (Test-Path -LiteralPath $target)) { Get-AuthenticodeSignature -LiteralPath $target } else { $null }
            [pscustomobject]@{
                path = $_.FullName
                target = $target
                signature = $(if ($trust) { [string]$trust.Status } else { $null })
                signer = $(if ($trust) { [string]$trust.SignerCertificate.Subject } else { $null })
                length = [long]$_.Length
                last_write_time = $_.LastWriteTimeUtc.ToString('o')
            }
        })
    }
}

$unsignedDrivers = @(Get-CimInstance Win32_PnPSignedDriver |
    Where-Object { $_.IsSigned -eq $false } |
    Select-Object -First 100 |
    ForEach-Object { [pscustomobject]@{ device = $_.DeviceName; provider = $_.DriverProviderName; version = $_.DriverVersion; path = $_.InfName } })

$systemDlls = @('amsi.dll', 'ntdll.dll', 'kernel32.dll', 'advapi32.dll') | ForEach-Object {
    $path = Join-Path $env:windir "System32\$_"
    $file = Get-Item -LiteralPath $path
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256
    [pscustomobject]@{
        name = $_
        path = $path
        version = $file.VersionInfo.FileVersion
        signature = [string]$signature.Status
        signer = [string]$signature.SignerCertificate.Subject
        sha256 = $hash.Hash
    }
}

$rdpPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$lsaPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
$hvciPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
$uacPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

$defenderSnapshot = $null
if ($mpStatus) {
    $signatureUpdated = $null
    if ($mpStatus.AntivirusSignatureLastUpdated) {
        $signatureUpdated = $mpStatus.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')
    }
    $defenderStatusSnapshot = [pscustomobject]@{
        am_service = [bool]$mpStatus.AMServiceEnabled
        antivirus = [bool]$mpStatus.AntivirusEnabled
        antispyware = [bool]$mpStatus.AntispywareEnabled
        realtime = [bool]$mpStatus.RealTimeProtectionEnabled
        behavior_monitor = [bool]$mpStatus.BehaviorMonitorEnabled
        ioav = [bool]$mpStatus.IoavProtectionEnabled
        network_inspection = [bool]$mpStatus.NISEnabled
        tamper_protected = [bool]$mpStatus.IsTamperProtected
        signature_version = [string]$mpStatus.AntivirusSignatureVersion
        signature_updated = $signatureUpdated
        quick_scan_age = [long]$mpStatus.QuickScanAge
        full_scan_age = [long]$mpStatus.FullScanAge
    }
    $defenderPreferencesSnapshot = [pscustomobject]@{
        disable_realtime = [bool]$mpPreference.DisableRealtimeMonitoring
        disable_behavior = [bool]$mpPreference.DisableBehaviorMonitoring
        disable_ioav = [bool]$mpPreference.DisableIOAVProtection
        cloud_reporting = [int]$mpPreference.MAPSReporting
        sample_submission = [int]$mpPreference.SubmitSamplesConsent
        cloud_block_level = [int]$mpPreference.CloudBlockLevel
        network_protection = [int]$mpPreference.EnableNetworkProtection
        controlled_folder_access = [int]$mpPreference.EnableControlledFolderAccess
        pua_protection = [int]$mpPreference.PUAProtection
        scan_downloads = -not ([bool]$mpPreference.DisableArchiveScanning)
        exclusions = [pscustomobject]@{
            paths = @($mpPreference.ExclusionPath)
            processes = @($mpPreference.ExclusionProcess)
            extensions = @($mpPreference.ExclusionExtension)
            ips = @($mpPreference.ExclusionIpAddress)
        }
        asr_rule_ids = @($mpPreference.AttackSurfaceReductionRules_Ids)
        asr_rule_actions = @($mpPreference.AttackSurfaceReductionRules_Actions)
    }
    $defenderSnapshot = [pscustomobject]@{
        status = $defenderStatusSnapshot
        preferences = $defenderPreferencesSnapshot
    }
}

$snapshot = [pscustomobject]@{
    collected_at = [DateTime]::UtcNow.ToString('o')
    host = [pscustomobject]@{
        computer_name = $env:COMPUTERNAME
        user_name = $env:USERNAME
        os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture)
        powershell_version = $PSVersionTable.PSVersion.ToString()
        language_mode = $ExecutionContext.SessionState.LanguageMode.ToString()
    }
    amsi = [pscustomobject]@{
        providers = $providers
        dlls = @($systemDlls)
    }
    defender = $defenderSnapshot
    telemetry = [pscustomobject]@{
        script_block_logging = [bool]((Get-RegistryValue $scriptBlockPath 'EnableScriptBlockLogging' 0) -eq 1)
        script_block_invocation_logging = [bool]((Get-RegistryValue $scriptBlockPath 'EnableScriptBlockInvocationLogging' 0) -eq 1)
        module_logging = [bool]((Get-RegistryValue $moduleLogPath 'EnableModuleLogging' 0) -eq 1)
        transcription = [bool]((Get-RegistryValue $transcriptionPath 'EnableTranscripting' 0) -eq 1)
        transcription_output = [string](Get-RegistryValue $transcriptionPath 'OutputDirectory' '')
        include_invocation_headers = [bool]((Get-RegistryValue $transcriptionPath 'EnableInvocationHeader' 0) -eq 1)
        event_logs = $eventLogs
        sysmon_services = $sysmonServices
    }
    platform_protection = [pscustomobject]@{
        secure_boot = $secureBoot
        tpm_present = $(if ($tpm) { [bool]$tpm.TpmPresent } else { $false })
        tpm_ready = $(if ($tpm) { [bool]$tpm.TpmReady } else { $false })
        device_guard_security_services_configured = @($deviceGuard.SecurityServicesConfigured)
        device_guard_security_services_running = @($deviceGuard.SecurityServicesRunning)
        vbs_status = [int]$deviceGuard.VirtualizationBasedSecurityStatus
        user_mode_code_integrity = [int]$deviceGuard.UsermodeCodeIntegrityPolicyEnforcementStatus
        kernel_mode_code_integrity = [int]$deviceGuard.CodeIntegrityPolicyEnforcementStatus
        hvci_enabled = [bool]((Get-RegistryValue $hvciPath 'Enabled' 0) -eq 1)
        lsa_ppl = [int](Get-RegistryValue $lsaPath 'RunAsPPL' 0)
        credential_guard_configured = @($deviceGuard.SecurityServicesConfigured) -contains 1
        credential_guard_running = @($deviceGuard.SecurityServicesRunning) -contains 1
        rdp_nla = [bool]((Get-RegistryValue $rdpPath 'UserAuthentication' 0) -eq 1)
        uac_enabled = [bool]((Get-RegistryValue $uacPath 'EnableLUA' 0) -eq 1)
        consent_prompt_behavior_admin = [int](Get-RegistryValue $uacPath 'ConsentPromptBehaviorAdmin' 0)
        firewall_profiles = $firewall
        app_locker = $appLocker
    }
    persistence = [pscustomobject]@{
        run_keys = $runKeys
        startup_entries = $startupEntries
        scheduled_tasks_non_microsoft = $nonMicrosoftTasks
        auto_services_not_running = $autoServicesNotRunning
        wmi_filters = $wmiFilters
        wmi_consumers = $wmiConsumers
        wmi_bindings = $wmiBindings
        unsigned_drivers = $unsignedDrivers
    }
}

$snapshot | ConvertTo-Json -Depth 10 -Compress
