from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from core.red_mode.models import RedCheck
from core.red_mode.platform import IS_WINDOWS, IS_WSL

PROFILE_CATEGORIES = {
    "quick": {"integrity", "defender", "platform"},
    "amsi": {"integrity"},
    "defender": {"defender"},
    "telemetry": {"telemetry"},
    "persistence": {"persistence", "platform"},
    "impact": {"integrity", "defender", "telemetry", "impact"},
    "full": {
        "integrity",
        "defender",
        "telemetry",
        "persistence",
        "platform",
        "impact",
    },
}


def _check(
    check_id: str,
    category: str,
    status: str,
    title: str,
    detail: str,
    recommendation: str = "",
    attack_id: str = "",
    **evidence: Any,
) -> RedCheck:
    return RedCheck(
        id=check_id,
        category=category,
        status=status,
        title=title,
        detail=detail,
        recommendation=recommendation,
        attack_id=attack_id,
        evidence=evidence,
    )


def _enabled_check(
    check_id: str, category: str, title: str, value: Any, recommendation: str
) -> RedCheck:
    enabled = value is True
    return _check(
        check_id,
        category,
        "PASS" if enabled else "FAIL",
        title,
        f"enabled={enabled}",
        "" if enabled else recommendation,
        value=value,
    )


def _integrity_checks(
    snapshot: dict, native_probe: list[dict], amsi_scan: dict
) -> list[RedCheck]:
    checks: list[RedCheck] = []
    dlls = snapshot.get("amsi", {}).get("dlls", [])
    for dll in dlls:
        valid = str(dll.get("signature", "")).lower() == "valid"
        checks.append(
            _check(
                f"INTEGRITY-DLL-{str(dll.get('name', 'unknown')).upper()}",
                "integrity",
                "PASS" if valid else "FAIL",
                "Assinatura do componente do sistema",
                f"{dll.get('name')}: assinatura={dll.get('signature')}; versão={dll.get('version')}",
                "Restaure o componente pelo Windows servicing e investigue alteração em System32."
                if not valid
                else "",
                path=dll.get("path"),
                sha256=dll.get("sha256"),
                signer=dll.get("signer"),
            )
        )

    providers = snapshot.get("amsi", {}).get("providers") or []
    checks.append(
        _check(
            "AMSI-PROVIDERS",
            "integrity",
            "PASS" if providers else "FAIL",
            "Provedores AMSI registrados",
            f"registered={len(providers)}",
            "Repare a integração do antivírus com AMSI." if not providers else "",
            providers=providers,
        )
    )

    for item in native_probe:
        export = item.get("Export", "unknown")
        clean = item.get("Status") == "PASS" and item.get("BytesMatch") is True
        status = "PASS" if clean else "FAIL"
        checks.append(
            _check(
                f"NATIVE-{str(export).upper()}",
                "integrity",
                status,
                "Integridade de exportação nativa",
                (
                    f"{item.get('Module')}!{export}: status={item.get('Status')}; "
                    f"bytes_match={item.get('BytesMatch')}; protection={item.get('MemoryProtection')}; "
                    f"writable_executable={item.get('WritableExecutable')}; suspicious={item.get('SuspiciousPrologue')}"
                ),
                "Isole o host e valide a DLL carregada contra uma imagem confiável do mesmo build."
                if not clean
                else "",
                loaded_bytes=item.get("LoadedBytes"),
                clean_bytes=item.get("CleanBytes"),
                error=item.get("Error"),
            )
        )

    available = amsi_scan.get("available") is True
    checks.append(
        _enabled_check(
            "AMSI-NATIVE-API",
            "integrity",
            "API AMSI operacional",
            available,
            "Repare AMSI/Defender e repita a validação.",
        )
    )
    if available:
        benign_ok = amsi_scan.get("benign_allowed") is True
        detected = amsi_scan.get("test_detected") is True
        checks.append(
            _check(
                "AMSI-BENIGN-CONTROL",
                "integrity",
                "PASS" if benign_ok else "FAIL",
                "Controle benigno AMSI",
                f"allowed={benign_ok}; result={amsi_scan.get('benign_result')}",
                "Investigue falso positivo ou corrupção na cadeia AMSI."
                if not benign_ok
                else "",
            )
        )
        checks.append(
            _check(
                "AMSI-TEST-DETECTION",
                "integrity",
                "PASS" if detected else "FAIL",
                "Detecção do marcador de teste em memória",
                f"detected={detected}; result={amsi_scan.get('test_result')}",
                "Revise o provedor AMSI e a proteção em tempo real; nenhum arquivo de teste foi gravado."
                if not detected
                else "",
            )
        )
    return checks


def _defender_checks(snapshot: dict) -> list[RedCheck]:
    defender = snapshot.get("defender") or {}
    status = defender.get("status") or {}
    preferences = defender.get("preferences") or {}
    if not defender:
        return [
            _check(
                "DEFENDER-AVAILABLE",
                "defender",
                "FAIL",
                "Microsoft Defender disponível",
                "snapshot indisponível",
                "Verifique serviço, permissões e produto antimalware ativo.",
            )
        ]

    checks = [
        _enabled_check(
            "DEFENDER-AVAILABLE", "defender", "Microsoft Defender disponível", True, ""
        )
    ]
    for key, title in (
        ("am_service", "Serviço antimalware"),
        ("antivirus", "Antivírus"),
        ("realtime", "Proteção em tempo real"),
        ("behavior_monitor", "Monitoramento comportamental"),
        ("ioav", "Inspeção de downloads"),
        ("network_inspection", "Inspeção de rede"),
    ):
        checks.append(
            _enabled_check(
                f"DEFENDER-{key.upper()}",
                "defender",
                title,
                status.get(key),
                f"Habilite {title.lower()} por política corporativa.",
            )
        )

    tamper = status.get("tamper_protected") is True
    checks.append(
        _check(
            "DEFENDER-TAMPER",
            "defender",
            "PASS" if tamper else "WARN",
            "Proteção contra adulteração",
            f"enabled={tamper}",
            "Habilite Tamper Protection no portal ou nas configurações do Defender."
            if not tamper
            else "",
        )
    )

    signature_date = status.get("signature_updated")
    age_days = None
    try:
        parsed = datetime.fromisoformat(str(signature_date).replace("Z", "+00:00"))
        age_days = (
            datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)
        ).total_seconds() / 86400
    except (TypeError, ValueError):
        pass
    fresh = age_days is not None and age_days <= 3
    checks.append(
        _check(
            "DEFENDER-SIGNATURE-FRESHNESS",
            "defender",
            "PASS" if fresh else "WARN",
            "Atualização das assinaturas",
            f"version={status.get('signature_version')}; updated={signature_date}; age_days={None if age_days is None else round(age_days, 1)}",
            "Atualize as assinaturas e investigue falhas de atualização."
            if not fresh
            else "",
        )
    )

    for key, title in (
        ("disable_realtime", "Política não desabilita tempo real"),
        ("disable_behavior", "Política não desabilita comportamento"),
        ("disable_ioav", "Política não desabilita IOAV"),
    ):
        safe = preferences.get(key) is False
        checks.append(
            _check(
                f"DEFENDER-{key.upper()}",
                "defender",
                "PASS" if safe else "FAIL",
                title,
                f"disabled={preferences.get(key)}",
                "Remova a política de desativação." if not safe else "",
            )
        )

    for key, title in (
        ("cloud_reporting", "Proteção entregue pela nuvem"),
        ("sample_submission", "Envio seguro de amostras"),
        ("network_protection", "Network Protection"),
        ("pua_protection", "Bloqueio de aplicações potencialmente indesejadas"),
    ):
        value = preferences.get(key)
        enabled = isinstance(value, int) and value > 0
        checks.append(
            _check(
                f"DEFENDER-{key.upper()}",
                "defender",
                "PASS" if enabled else "WARN",
                title,
                f"mode={value}",
                f"Defina {title} em modo de bloqueio por política."
                if not enabled
                else "",
            )
        )

    cfa = preferences.get("controlled_folder_access")
    checks.append(
        _check(
            "DEFENDER-CFA",
            "defender",
            "PASS" if isinstance(cfa, int) and cfa > 0 else "WARN",
            "Controlled Folder Access",
            f"mode={cfa}",
            "Avalie habilitar inicialmente em auditoria e depois em bloqueio."
            if not cfa
            else "",
        )
    )

    exclusions = preferences.get("exclusions") or {}
    flattened = [
        str(value)
        for values in exclusions.values()
        for value in (values or [])
        if value not in (None, "")
    ]
    restricted = any(
        "administrator" in value.lower() or value.startswith("N/A:")
        for value in flattened
    )
    actual = [
        value
        for value in flattened
        if "administrator" not in value.lower() and not value.startswith("N/A:")
    ]
    exclusion_status = "INFO" if restricted else "WARN" if actual else "PASS"
    detail = (
        "visibilidade limitada: execute como administrador para auditar exclusões"
        if restricted
        else f"configured={len(actual)}"
    )
    checks.append(
        _check(
            "DEFENDER-EXCLUSIONS",
            "defender",
            exclusion_status,
            "Exclusões do Defender",
            detail,
            "Revise cada exclusão, limite caminho/processo e documente a justificativa."
            if actual
            else "",
            exclusions=actual,
        )
    )

    raw_rule_ids = preferences.get("asr_rule_ids") or []
    raw_actions = preferences.get("asr_rule_actions") or []
    pairs = [
        (str(rule_id), raw_actions[index] if index < len(raw_actions) else None)
        for index, rule_id in enumerate(raw_rule_ids)
        if rule_id not in (None, "")
    ]
    rule_ids = [rule_id for rule_id, _ in pairs]
    actions = [action for _, action in pairs]
    configured = bool(rule_ids) and all(
        action not in (None, 0, "0") for action in actions
    )
    checks.append(
        _check(
            "DEFENDER-ASR",
            "defender",
            "PASS" if configured else "WARN",
            "Attack Surface Reduction",
            f"configured_rules={len(rule_ids)}",
            "Implante regras ASR em auditoria, meça incompatibilidades e evolua para bloqueio."
            if not configured
            else "",
            rule_ids=rule_ids,
            actions=actions,
        )
    )
    return checks


def _telemetry_checks(
    snapshot: dict, canaries: dict, detections: dict
) -> list[RedCheck]:
    telemetry = snapshot.get("telemetry") or {}
    checks: list[RedCheck] = []
    for key, title in (
        ("script_block_logging", "PowerShell Script Block Logging"),
        ("module_logging", "PowerShell Module Logging"),
        ("transcription", "PowerShell Transcription"),
    ):
        enabled = telemetry.get(key) is True
        checks.append(
            _check(
                f"TELEMETRY-{key.upper()}",
                "telemetry",
                "PASS" if enabled else "WARN",
                title,
                f"enabled={enabled}",
                f"Habilite {title} por GPO e proteja o destino dos logs."
                if not enabled
                else "",
                attack_id="T1059.001",
            )
        )

    for log in telemetry.get("event_logs") or []:
        name = str(log.get("name"))
        exists = log.get("exists") is True
        accessible = log.get("accessible", True) is True
        enabled = log.get("enabled") is True
        critical = name in {
            "Security",
            "System",
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-PowerShell/Operational",
        }
        state = exists and enabled
        result = (
            "INFO"
            if exists and not accessible
            else "PASS"
            if state
            else "FAIL"
            if critical
            else "WARN"
        )
        recommendation = (
            "Execute como administrador para confirmar configuração e retenção deste canal."
            if exists and not accessible
            else "Habilite o canal, dimensione a retenção e encaminhe para o SIEM."
            if not state
            else ""
        )
        checks.append(
            _check(
                f"EVENTLOG-{name.upper().replace('/', '-').replace(' ', '-')}",
                "telemetry",
                result,
                "Canal de eventos",
                f"{name}: exists={exists}; accessible={accessible}; enabled={log.get('enabled')}; records={log.get('record_count')}; max_bytes={log.get('maximum_size_bytes')}",
                recommendation,
                error=log.get("error"),
            )
        )

    sysmon = telemetry.get("sysmon_services") or []
    running = any(str(item.get("state", "")).lower() == "running" for item in sysmon)
    checks.append(
        _check(
            "TELEMETRY-SYSMON",
            "telemetry",
            "PASS" if running else "WARN",
            "Sysmon",
            f"running={running}; services={len(sysmon)}",
            "Instale e mantenha uma configuração Sysmon versionada se fizer parte da estratégia de telemetria."
            if not running
            else "",
        )
    )

    for name, result in (canaries.get("actions") or {}).items():
        status = result.get("status", "FAIL")
        checks.append(
            _check(
                f"CANARY-{name.upper()}",
                "telemetry",
                status,
                "Canário benigno local",
                f"{name}: {result.get('detail')}",
                "Corrija o subsistema local e repita o teste."
                if status != "PASS"
                else "",
                attack_id={
                    "process": "T1059.006",
                    "shell": "T1059.001",   # renamed from 'powershell' for cross-platform
                    "powershell": "T1059.001",
                    "file": "T1074.001",
                    "registry": "T1112",
                    "tcp_loopback": "T1095",
                    "named_pipe": "T1559",
                    "credential_dump": "T1003",
                    "persistence_sim": "T1053.005",
                }.get(name, ""),
                **(result.get("evidence") or {}),
            )
        )

    for event in canaries.get("events") or []:
        log = event.get("log", "unknown")
        event_id = event.get("event_id", "unknown")
        if event.get("observed"):
            status = "PASS"
            recommendation = ""
        elif not event.get("accessible"):
            status = "INFO"
            recommendation = (
                "Execute com privilégios adequados para validar a observação do evento."
            )
        else:
            status = "WARN"
            recommendation = "Revise auditoria, política do canal e pipeline de coleta."
        checks.append(
            _check(
                f"CANARY-EVENT-{event_id}-{str(log).upper().replace('/', '-')}",
                "telemetry",
                status,
                "Observação do canário em evento",
                f"{log}/{event_id}: enabled={event.get('enabled')}; observed={event.get('observed')}; record_id={event.get('record_id')}",
                recommendation,
            )
        )

    mapping = detections.get("detections", {}) if isinstance(detections, dict) else {}
    for canary_id, record in mapping.items():
        validated = (
            isinstance(record, dict)
            and str(record.get("status", "")).lower() == "validated"
        )
        checks.append(
            _check(
                f"DETECTION-{canary_id}",
                "telemetry",
                "PASS" if validated else "WARN",
                "Mapeamento de detecção SIEM/EDR",
                f"{canary_id}: status={record.get('status') if isinstance(record, dict) else record}; rule={record.get('rule_id') if isinstance(record, dict) else None}",
                "Associe a evidência a uma regra e marque status=validated somente após confirmação no SIEM/EDR."
                if not validated
                else "",
            )
        )
    return checks


def _platform_checks(snapshot: dict) -> list[RedCheck]:
    platform = snapshot.get("platform_protection") or {}
    checks: list[RedCheck] = []
    values = (
        (
            "PLATFORM-SECURE-BOOT",
            "Secure Boot",
            platform.get("secure_boot"),
            "Confirme UEFI/Secure Boot; valor nulo pode indicar firmware sem suporte ou acesso limitado.",
        ),
        (
            "PLATFORM-TPM",
            "TPM pronto",
            platform.get("tpm_present") is True and platform.get("tpm_ready") is True,
            "Inicialize o TPM e aplique a política de proteção de chaves.",
        ),
        (
            "PLATFORM-VBS",
            "Virtualization Based Security",
            platform.get("vbs_status") == 2,
            "Habilite VBS após validar requisitos e compatibilidade.",
        ),
        (
            "PLATFORM-HVCI",
            "Memory Integrity / HVCI",
            platform.get("hvci_enabled") is True,
            "Habilite HVCI de forma controlada e valide drivers.",
        ),
        (
            "PLATFORM-LSA-PPL",
            "LSA protegido",
            int(platform.get("lsa_ppl") or 0) > 0,
            "Habilite proteção LSA por política e valide compatibilidade.",
        ),
        (
            "PLATFORM-CREDENTIAL-GUARD",
            "Credential Guard",
            platform.get("credential_guard_running") is True,
            "Habilite Credential Guard em endpoints compatíveis.",
        ),
        (
            "PLATFORM-UAC",
            "UAC",
            platform.get("uac_enabled") is True,
            "Habilite UAC e use prompts seguros para administradores.",
        ),
        (
            "PLATFORM-RDP-NLA",
            "RDP Network Level Authentication",
            platform.get("rdp_nla") is True,
            "Exija NLA quando RDP estiver habilitado.",
        ),
    )
    for check_id, title, value, recommendation in values:
        checks.append(
            _check(
                check_id,
                "platform",
                "PASS" if value else "WARN",
                title,
                f"enabled={bool(value)}",
                "" if value else recommendation,
            )
        )

    for firewall in platform.get("firewall_profiles") or []:
        enabled = firewall.get("enabled") is True
        logging = firewall.get("logging_blocked") is True
        checks.append(
            _check(
                f"FIREWALL-{str(firewall.get('name')).upper()}",
                "platform",
                "PASS" if enabled else "FAIL",
                "Perfil do Windows Firewall",
                f"{firewall.get('name')}: enabled={enabled}; inbound={firewall.get('default_inbound')}; log_blocked={logging}",
                "Habilite o firewall e registre conexões bloqueadas."
                if not enabled
                else "Considere habilitar log de bloqueios."
                if not logging
                else "",
            )
        )

    app_locker = platform.get("app_locker") or []
    checks.append(
        _check(
            "PLATFORM-APPLICATION-CONTROL",
            "platform",
            "PASS" if app_locker else "WARN",
            "Controle de aplicações",
            f"AppLocker_collections={len(app_locker)}",
            "Planeje WDAC ou AppLocker em auditoria antes do bloqueio."
            if not app_locker
            else "",
            collections=app_locker,
        )
    )
    return checks


def _suspicious_command(value: str) -> bool:
    lowered = value.lower()
    indicators = (
        "\\appdata\\",
        "\\temp\\",
        "-encodedcommand",
        " -enc ",
        "frombase64string",
        "javascript:",
        "wscript",
        "cscript",
    )
    return any(item in lowered for item in indicators)


def _persistence_checks(snapshot: dict) -> list[RedCheck]:
    persistence = snapshot.get("persistence") or {}
    checks: list[RedCheck] = []
    unsigned = persistence.get("unsigned_drivers") or []
    checks.append(
        _check(
            "PERSISTENCE-UNSIGNED-DRIVERS",
            "persistence",
            "FAIL" if unsigned else "PASS",
            "Drivers sem assinatura",
            f"count={len(unsigned)}",
            "Isole e investigue cada driver sem assinatura; remova somente após validação de impacto."
            if unsigned
            else "",
            attack_id="T1547",
            items=unsigned,
        )
    )

    for kind, key, attack_id in (
        ("Run/RunOnce", "run_keys", "T1060"),
        ("Startup folder", "startup_entries", "T1060"),
        ("Scheduled task", "scheduled_tasks_non_microsoft", "T1053.005"),
    ):
        items = persistence.get(key) or []
        suspect = []
        for item in items:
            material = (
                " ".join(str(value) for value in item.values())
                if isinstance(item, dict)
                else str(item)
            )
            signed = (
                isinstance(item, dict)
                and str(item.get("signature", "")).lower() == "valid"
            )
            if _suspicious_command(material) and not signed:
                suspect.append(item)
        checks.append(
            _check(
                f"PERSISTENCE-{key.upper()}",
                "persistence",
                "WARN" if suspect else "INFO",
                f"Inventário de persistência: {kind}",
                f"count={len(items)}; suspicious_heuristic={len(suspect)}",
                "Revise manualmente entradas sinalizadas e valide assinatura, proprietário e necessidade."
                if suspect
                else "Inventário informativo; mantenha uma baseline aprovada.",
                attack_id=attack_id,
                suspicious=suspect,
            )
        )

    consumers = persistence.get("wmi_consumers") or []
    bindings = persistence.get("wmi_bindings") or []
    filters = persistence.get("wmi_filters") or []
    has_wmi = bool(consumers)
    checks.append(
        _check(
            "PERSISTENCE-WMI",
            "persistence",
            "WARN" if has_wmi else "PASS",
            "Assinaturas WMI permanentes",
            f"filters={len(filters)}; consumers={len(consumers)}; bindings={len(bindings)}",
            "Valide proprietário e finalidade de cada assinatura WMI permanente."
            if has_wmi
            else "",
            attack_id="T1546.003",
            filters=filters,
            consumers=consumers,
            bindings=bindings,
        )
    )

    services = persistence.get("auto_services_not_running") or []
    checks.append(
        _check(
            "PERSISTENCE-AUTO-SERVICES",
            "persistence",
            "INFO",
            "Serviços automáticos fora de execução",
            f"count={len(services)}",
            "Compare com a baseline e investigue falhas inesperadas.",
            items=services,
        )
    )
    return checks


# ── Linux check functions ──────────────────────────────────────────────────────


def _linux_integrity_checks(snapshot: dict) -> list[RedCheck]:
    integrity = snapshot.get("integrity") or {}
    checks: list[RedCheck] = []
    libs = integrity.get("critical_libs") or []
    checks.append(
        _check(
            "LINUX-INTEGRITY-LIBS",
            "integrity",
            "PASS" if libs else "WARN",
            "Bibliotecas críticas do sistema verificadas",
            f"libs_hashed={len(libs)}",
            "Valide manualmente a integridade das bibliotecas e considere ativar IMA/EVM."
            if not libs
            else "",
            libs=libs,
        )
    )
    ima = integrity.get("ima_available", False)
    checks.append(
        _check(
            "LINUX-IMA",
            "integrity",
            "PASS" if ima else "WARN",
            "Integrity Measurement Architecture (IMA)",
            f"available={ima}",
            "Configure IMA/EVM no kernel para medição contínua de integridade."
            if not ima
            else "",
        )
    )
    return checks


def _linux_av_checks(snapshot: dict) -> list[RedCheck]:
    av = snapshot.get("av") or {}
    checks: list[RedCheck] = []

    installed = av.get("clamav_installed", False)
    running = av.get("clamav_running", False)
    db_updated = av.get("clamav_db_updated")

    checks.append(
        _check(
            "LINUX-AV-CLAMAV-INSTALLED",
            "defender",
            "PASS" if installed else "WARN",
            "ClamAV instalado",
            f"installed={installed}; version={av.get('clamav_version', '')}",
            "Instale o ClamAV: apt install clamav clamav-daemon"
            if not installed
            else "",
        )
    )
    if installed:
        checks.append(
            _check(
                "LINUX-AV-CLAMAV-RUNNING",
                "defender",
                "PASS" if running else "WARN",
                "Daemon ClamAV ativo",
                f"running={running}",
                "Habilite e inicie o serviço: systemctl enable --now clamav-daemon"
                if not running
                else "",
            )
        )
        # Signature freshness (warn if older than 3 days or unknown)
        fresh = False
        if db_updated:
            try:
                from datetime import datetime, timezone
                parsed = datetime.fromisoformat(db_updated.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds() / 86400
                fresh = age <= 3
            except (ValueError, TypeError):
                pass
        checks.append(
            _check(
                "LINUX-AV-SIGNATURES",
                "defender",
                "PASS" if fresh else "WARN",
                "Assinaturas ClamAV atualizadas",
                f"db_updated={db_updated}",
                "Execute freshclam para atualizar as assinaturas."
                if not fresh
                else "",
            )
        )

    chkrootkit = av.get("chkrootkit_available", False)
    rkhunter = av.get("rkhunter_available", False)
    checks.append(
        _check(
            "LINUX-AV-ROOTKIT-SCANNER",
            "defender",
            "PASS" if (chkrootkit or rkhunter) else "WARN",
            "Scanner de rootkit disponível",
            f"chkrootkit={chkrootkit}; rkhunter={rkhunter}",
            "Instale chkrootkit ou rkhunter para detecção de rootkits."
            if not (chkrootkit or rkhunter)
            else "",
        )
    )
    return checks


def _linux_telemetry_checks(snapshot: dict, canaries: dict, detections: dict) -> list[RedCheck]:
    telemetry = snapshot.get("telemetry") or {}
    checks: list[RedCheck] = []

    auditd = telemetry.get("auditd_running", False)
    checks.append(
        _check(
            "LINUX-TELEMETRY-AUDITD",
            "telemetry",
            "PASS" if auditd else "WARN",
            "auditd em execução",
            f"running={auditd}; rules={telemetry.get('auditd_rule_count', 0)}",
            "Instale e configure o auditd com regras de auditoria relevantes."
            if not auditd
            else "",
            attack_id="T1562.001",
        )
    )
    journald = telemetry.get("journald_running", False)
    checks.append(
        _check(
            "LINUX-TELEMETRY-JOURNALD",
            "telemetry",
            "PASS" if journald else "WARN",
            "systemd-journald em execução",
            f"running={journald}",
            "Verifique o serviço systemd-journald."
            if not journald
            else "",
        )
    )
    syslog = telemetry.get("syslog_running", False)
    checks.append(
        _check(
            "LINUX-TELEMETRY-SYSLOG",
            "telemetry",
            "PASS" if syslog else "WARN",
            "syslog em execução (rsyslog/syslog-ng)",
            f"running={syslog}",
            "Instale e configure rsyslog ou syslog-ng."
            if not syslog
            else "",
        )
    )
    for lf in telemetry.get("log_files") or []:
        exists = lf.get("exists", False)
        nonempty = lf.get("size_bytes", 0) > 0
        checks.append(
            _check(
                f"LINUX-LOGFILE-{lf['path'].replace('/', '-').upper().strip('-')}",
                "telemetry",
                "PASS" if (exists and nonempty) else "WARN" if exists else "INFO",
                "Arquivo de log presente",
                f"{lf['path']}: exists={exists}; size={lf.get('size_bytes', 0)}",
                f"Arquivo {lf['path']} ausente ou vazio — verifique o syslog."
                if not (exists and nonempty)
                else "",
            )
        )
    # Canary events on Linux (journald / syslog search)
    for name, result in (canaries.get("actions") or {}).items():
        status = result.get("status", "FAIL")
        checks.append(
            _check(
                f"CANARY-{name.upper()}",
                "telemetry",
                status,
                "Canário benigno local (Linux)",
                f"{name}: {result.get('detail')}",
                "Corrija o subsistema local e repita o teste."
                if status != "PASS"
                else "",
                attack_id={
                    "process": "T1059.006",
                    "shell": "T1059.004",
                    "file": "T1074.001",
                    "registry": "T1112",
                    "tcp_loopback": "T1095",
                    "named_pipe": "T1559",
                    "credential_dump": "T1003",
                    "persistence_sim": "T1098",
                }.get(name, ""),
                **(result.get("evidence") or {}),
            )
        )
    for event in canaries.get("events") or []:
        log = event.get("log", "unknown")
        observed = event.get("observed", False)
        accessible = event.get("accessible", False)
        status = "PASS" if observed else "INFO" if not accessible else "WARN"
        checks.append(
            _check(
                f"CANARY-EVENT-{str(log).replace('/', '-').upper()}",
                "telemetry",
                status,
                "Observação do canário em log (Linux)",
                f"{log}: observed={observed}; accessible={accessible}",
                "Configure encaminhamento de logs ao SIEM."
                if not observed and accessible
                else "",
            )
        )
    # Detection policy mapping
    mapping = detections.get("detections", {}) if isinstance(detections, dict) else {}
    for canary_id, record in mapping.items():
        validated = (
            isinstance(record, dict)
            and str(record.get("status", "")).lower() == "validated"
        )
        checks.append(
            _check(
                f"DETECTION-{canary_id}",
                "telemetry",
                "PASS" if validated else "WARN",
                "Mapeamento de detecção SIEM/EDR",
                f"{canary_id}: status={record.get('status') if isinstance(record, dict) else record}",
                "Associe a evidência a uma regra e marque status=validated."
                if not validated
                else "",
            )
        )
    return checks


def _linux_persistence_checks(snapshot: dict) -> list[RedCheck]:
    persistence = snapshot.get("persistence") or {}
    checks: list[RedCheck] = []

    user_cron = persistence.get("user_cron_entries") or []
    checks.append(
        _check(
            "LINUX-PERSISTENCE-CRON-USER",
            "persistence",
            "INFO" if user_cron else "PASS",
            "Crontab do usuário",
            f"entries={len(user_cron)}",
            "Revise cada entrada do crontab e valide origem e necessidade."
            if user_cron
            else "",
            attack_id="T1053.003",
            items=user_cron,
        )
    )
    sys_cron = persistence.get("system_cron_files") or []
    checks.append(
        _check(
            "LINUX-PERSISTENCE-CRON-SYSTEM",
            "persistence",
            "INFO",
            "Arquivos de cron do sistema",
            f"files={len(sys_cron)}",
            "Mantenha uma baseline aprovada dos scripts de cron do sistema.",
            attack_id="T1053.003",
            items=sys_cron[:20],
        )
    )
    rc_local = persistence.get("rc_local_present", False)
    checks.append(
        _check(
            "LINUX-PERSISTENCE-RC-LOCAL",
            "persistence",
            "WARN" if rc_local else "PASS",
            "/etc/rc.local presente",
            f"exists={rc_local}",
            "Revise o conteúdo de /etc/rc.local; prefira units systemd."
            if rc_local
            else "",
            attack_id="T1037.004",
        )
    )
    non_std = persistence.get("non_standard_services") or []
    checks.append(
        _check(
            "LINUX-PERSISTENCE-SERVICES",
            "persistence",
            "INFO",
            "Serviços systemd não-padrão",
            f"count={len(non_std)}",
            "Inventarie e documente cada serviço não-padrão.",
            attack_id="T1543.002",
            items=non_std[:20],
        )
    )
    return checks


def _linux_platform_checks(snapshot: dict) -> list[RedCheck]:
    platform = snapshot.get("platform") or {}
    checks: list[RedCheck] = []

    aslr = platform.get("aslr")
    checks.append(
        _check(
            "LINUX-PLATFORM-ASLR",
            "platform",
            "PASS" if aslr == 2 else "WARN" if aslr == 1 else "FAIL",
            "ASLR (randomize_va_space)",
            f"value={aslr} (0=off, 1=conservative, 2=full)",
            "Defina kernel.randomize_va_space=2 em /etc/sysctl.conf."
            if aslr != 2
            else "",
        )
    )
    kptr = platform.get("kptr_restrict")
    checks.append(
        _check(
            "LINUX-PLATFORM-KPTR-RESTRICT",
            "platform",
            "PASS" if kptr and int(kptr) >= 1 else "WARN",
            "Kptr restrict (ocultar ponteiros do kernel)",
            f"value={kptr}",
            "Defina kernel.kptr_restrict=2 em /etc/sysctl.conf."
            if not (kptr and int(kptr) >= 1)
            else "",
        )
    )
    dmesg = platform.get("dmesg_restrict")
    checks.append(
        _check(
            "LINUX-PLATFORM-DMESG-RESTRICT",
            "platform",
            "PASS" if dmesg and int(dmesg) >= 1 else "WARN",
            "dmesg restrict",
            f"value={dmesg}",
            "Defina kernel.dmesg_restrict=1 em /etc/sysctl.conf."
            if not (dmesg and int(dmesg) >= 1)
            else "",
        )
    )
    apparmor = platform.get("apparmor_enabled", False)
    selinux = platform.get("selinux_enabled", False)
    mac_ok = apparmor or selinux
    checks.append(
        _check(
            "LINUX-PLATFORM-MAC",
            "platform",
            "PASS" if mac_ok else "WARN",
            "Controle de Acesso Mandatório (AppArmor / SELinux)",
            f"apparmor={apparmor} profiles={platform.get('apparmor_profiles', 0)}; selinux={selinux} mode={platform.get('selinux_mode', '')}",
            "Habilite AppArmor ou SELinux e configure políticas para serviços críticos."
            if not mac_ok
            else "",
        )
    )
    ufw = platform.get("ufw_active", False)
    ipt = platform.get("iptables_rules", 0)
    fw_ok = ufw or ipt > 0
    checks.append(
        _check(
            "LINUX-PLATFORM-FIREWALL",
            "platform",
            "PASS" if fw_ok else "WARN",
            "Firewall ativo (UFW / iptables)",
            f"ufw_active={ufw}; iptables_rules={ipt}",
            "Configure o UFW ou regras iptables para restringir tráfego de entrada."
            if not fw_ok
            else "",
        )
    )
    root_login = str(platform.get("ssh_permit_root_login", "yes")).lower()
    ssh_root_ok = root_login in ("no", "without-password", "prohibit-password")
    checks.append(
        _check(
            "LINUX-PLATFORM-SSH-ROOT",
            "platform",
            "PASS" if ssh_root_ok else "WARN",
            "SSH: PermitRootLogin",
            f"value={root_login}",
            "Defina PermitRootLogin no /etc/ssh/sshd_config."
            if not ssh_root_ok
            else "",
        )
    )
    pw_auth = str(platform.get("ssh_password_auth", "yes")).lower()
    ssh_pw_ok = pw_auth == "no"
    checks.append(
        _check(
            "LINUX-PLATFORM-SSH-PASSWORD",
            "platform",
            "PASS" if ssh_pw_ok else "WARN",
            "SSH: PasswordAuthentication",
            f"value={pw_auth}",
            "Desabilite autenticação por senha e use apenas chaves: PasswordAuthentication no."
            if not ssh_pw_ok
            else "",
        )
    )
    nopasswd = platform.get("sudoers_nopasswd_count", 0)
    checks.append(
        _check(
            "LINUX-PLATFORM-SUDO-NOPASSWD",
            "platform",
            "WARN" if nopasswd > 0 else "PASS",
            "Entradas NOPASSWD no sudoers",
            f"count={nopasswd}",
            "Revise e remova ou restrinja entradas NOPASSWD no sudoers."
            if nopasswd > 0
            else "",
            attack_id="T1548.003",
        )
    )
    return checks


# ── Orchestrator ───────────────────────────────────────────────────────────────


def evaluate(
    profile: str,
    snapshot: dict,
    native_probe: list[dict],
    amsi_scan: dict,
    canaries: dict,
    detections: dict | None = None,
) -> list[RedCheck]:
    categories = PROFILE_CATEGORIES[profile]
    checks: list[RedCheck] = []

    is_linux = snapshot.get("_os") == "linux"

    if is_linux:
        # ── Linux path ──────────────────────────────────────────────
        if "integrity" in categories:
            checks.extend(_linux_integrity_checks(snapshot))
        if "defender" in categories:
            checks.extend(_linux_av_checks(snapshot))
        if "telemetry" in categories:
            checks.extend(_linux_telemetry_checks(snapshot, canaries, detections or {}))
        if "persistence" in categories:
            checks.extend(_linux_persistence_checks(snapshot))
        if "platform" in categories:
            checks.extend(_linux_platform_checks(snapshot))
    else:
        # ── Windows path ────────────────────────────────────────────
        if "integrity" in categories:
            checks.extend(_integrity_checks(snapshot, native_probe, amsi_scan))
        if "defender" in categories:
            checks.extend(_defender_checks(snapshot))
        if "telemetry" in categories:
            checks.extend(_telemetry_checks(snapshot, canaries, detections or {}))
        if "persistence" in categories:
            checks.extend(_persistence_checks(snapshot))
        if "platform" in categories:
            checks.extend(_platform_checks(snapshot))

    return checks
