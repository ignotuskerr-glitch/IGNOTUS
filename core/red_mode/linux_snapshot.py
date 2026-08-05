"""
core/red_mode/linux_snapshot.py

Collects a security snapshot of the local Linux system using standard
CLI tools available on most distributions (no root required for most
checks; some checks degrade gracefully when unprivileged).

Equivalent to the PowerShell red_mode_snapshot.ps1 on Windows.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any


# ── helpers ───────────────────────────────────────────────────────────────────


def _run(*args: str, timeout: int = 10) -> str:
    """Run a command and return stdout; return '' on any error."""
    try:
        result = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _file(path: str) -> str:
    """Read a /proc or /sys file; return '' if missing or unreadable."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _which(name: str) -> str | None:
    return shutil.which(name)


# ── integrity ─────────────────────────────────────────────────────────────────


def _collect_integrity() -> dict[str, Any]:
    """SHA-256 hashes of critical system libraries and kernel module state."""
    lib_candidates = [
        "/lib/x86_64-linux-gnu/libpam.so.0",
        "/lib/aarch64-linux-gnu/libpam.so.0",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/aarch64-linux-gnu/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/aarch64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
    ]
    libs: list[dict] = []
    for path in lib_candidates:
        p = Path(path)
        if not p.is_file():
            continue
        sha = _run("sha256sum", path)
        digest = sha.split()[0] if sha else "error"
        try:
            size = p.stat().st_size
        except OSError:
            size = -1
        libs.append({"path": path, "sha256": digest, "size_bytes": size})

    # Loaded kernel modules
    modules_raw = _file("/proc/modules")
    modules = [line.split()[0] for line in modules_raw.splitlines() if line.strip()]

    # IMA (Integrity Measurement Architecture)
    ima_policy = _file("/sys/kernel/security/ima/policy")
    ima_available = bool(ima_policy)

    return {
        "critical_libs": libs,
        "kernel_modules_count": len(modules),
        "ima_available": ima_available,
    }


# ── antivirus / av ────────────────────────────────────────────────────────────


def _collect_av() -> dict[str, Any]:
    """Probe installed AV / rootkit detection tools."""
    clamav_installed = bool(_which("clamdscan") or _which("clamscan"))
    clamav_running = False
    clamav_version = ""
    if clamav_installed:
        ver = _run("clamdscan", "--version", timeout=5)
        if not ver:
            ver = _run("clamscan", "--version", timeout=5)
        clamav_version = ver.splitlines()[0] if ver else ""
        # Check if clamd daemon is running
        clamd_status = _run("systemctl", "is-active", "clamav-daemon", timeout=5)
        clamav_running = clamd_status == "active"

    chkrootkit = bool(_which("chkrootkit"))
    rkhunter = bool(_which("rkhunter"))

    # freshclam last update (indicates signature freshness)
    freshclam_db = Path("/var/lib/clamav/daily.cvd")
    if not freshclam_db.exists():
        freshclam_db = Path("/var/lib/clamav/daily.cld")
    clamav_db_mtime: str | None = None
    if freshclam_db.exists():
        try:
            import datetime
            mtime = freshclam_db.stat().st_mtime
            clamav_db_mtime = datetime.datetime.utcfromtimestamp(mtime).isoformat() + "Z"
        except OSError:
            pass

    return {
        "clamav_installed": clamav_installed,
        "clamav_running": clamav_running,
        "clamav_version": clamav_version,
        "clamav_db_updated": clamav_db_mtime,
        "chkrootkit_available": chkrootkit,
        "rkhunter_available": rkhunter,
    }


# ── telemetry ─────────────────────────────────────────────────────────────────


def _collect_telemetry() -> dict[str, Any]:
    """Check logging subsystems: auditd, journald, rsyslog/syslog-ng."""
    # auditd
    auditd_running = _run("systemctl", "is-active", "auditd", timeout=5) == "active"
    auditctl_rules = ""
    if _which("auditctl"):
        auditctl_rules = _run("auditctl", "-l", timeout=5)
    auditd_rule_count = len([l for l in auditctl_rules.splitlines() if l.strip() and not l.startswith("#")])

    # journald
    journald_running = _run("systemctl", "is-active", "systemd-journald", timeout=5) == "active"

    # syslog
    rsyslog = _run("systemctl", "is-active", "rsyslog", timeout=5) == "active"
    syslog_ng = _run("systemctl", "is-active", "syslog-ng", timeout=5) == "active"
    syslog_running = rsyslog or syslog_ng

    # Check key log files exist and are non-empty
    log_files: list[dict] = []
    for lf in ("/var/log/auth.log", "/var/log/syslog", "/var/log/messages", "/var/log/secure"):
        p = Path(lf)
        exists = p.exists()
        try:
            size = p.stat().st_size if exists else 0
        except OSError:
            size = 0
        log_files.append({"path": lf, "exists": exists, "size_bytes": size})

    return {
        "auditd_running": auditd_running,
        "auditd_rule_count": auditd_rule_count,
        "journald_running": journald_running,
        "syslog_running": syslog_running,
        "log_files": log_files,
    }


# ── persistence ───────────────────────────────────────────────────────────────


def _collect_persistence() -> dict[str, Any]:
    """Enumerate common Linux persistence mechanisms."""
    # User crontabs
    user_crontab = _run("crontab", "-l", timeout=5)
    user_cron_entries = [l for l in user_crontab.splitlines() if l.strip() and not l.startswith("#")]

    # System cron dirs
    system_cron_paths = [
        "/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly",
        "/etc/cron.monthly", "/etc/cron.hourly",
    ]
    system_cron_entries: list[str] = []
    for d in system_cron_paths:
        p = Path(d)
        if p.is_dir():
            system_cron_entries.extend(str(f) for f in p.iterdir() if f.is_file())

    # /etc/rc.local
    rc_local = _file("/etc/rc.local")

    # Non-standard systemd services
    systemd_raw = _run("systemctl", "list-units", "--type=service", "--all",
                       "--no-legend", "--no-pager", timeout=10)
    non_std_services: list[str] = []
    vendor_prefixes = ("systemd-", "dbus", "udev", "network", "ssh", "cron",
                       "rsyslog", "avahi", "cups", "bluetooth")
    for line in systemd_raw.splitlines():
        parts = line.split()
        if not parts:
            continue
        svc = parts[0].replace(".service", "")
        if not any(svc.startswith(p) for p in vendor_prefixes):
            non_std_services.append(parts[0])

    # /etc/init.d scripts
    initd_scripts: list[str] = []
    initd = Path("/etc/init.d")
    if initd.is_dir():
        initd_scripts = [f.name for f in initd.iterdir() if f.is_file()]

    # ~/.bashrc / ~/.profile modifications (simple check)
    home = Path.home()
    shell_files: list[dict] = []
    for sf in (".bashrc", ".bash_profile", ".profile", ".zshrc"):
        p = home / sf
        if p.exists():
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            shell_files.append({"file": str(p), "size_bytes": size})

    return {
        "user_cron_entries": user_cron_entries,
        "system_cron_files": system_cron_entries,
        "rc_local_present": bool(rc_local),
        "non_standard_services": non_std_services[:50],
        "initd_scripts": initd_scripts,
        "shell_init_files": shell_files,
    }


# ── platform ──────────────────────────────────────────────────────────────────


def _collect_platform() -> dict[str, Any]:
    """Kernel hardening, MAC, firewall, SSH, sudo."""
    # ASLR  (0=off, 1=conservative, 2=full)
    aslr = _file("/proc/sys/kernel/randomize_va_space")
    aslr_value = int(aslr) if aslr.isdigit() else None

    # Kernel pointer exposure
    kptr_restrict = _file("/proc/sys/kernel/kptr_restrict")

    # dmesg restrict
    dmesg_restrict = _file("/proc/sys/kernel/dmesg_restrict")

    # AppArmor
    apparmor_enabled = Path("/sys/kernel/security/apparmor").exists()
    apparmor_profiles = 0
    if apparmor_enabled and _which("aa-status"):
        aa_out = _run("aa-status", "--json", timeout=10)
        try:
            aa_data = json.loads(aa_out)
            apparmor_profiles = len(aa_data.get("profiles", {}))
        except (json.JSONDecodeError, AttributeError):
            pass

    # SELinux
    selinux_enabled = Path("/sys/fs/selinux").exists()
    selinux_mode = ""
    if selinux_enabled and _which("getenforce"):
        selinux_mode = _run("getenforce", timeout=5)

    # Firewall
    ufw_active = False
    if _which("ufw"):
        ufw_out = _run("ufw", "status", timeout=5)
        ufw_active = "active" in ufw_out.lower()
    iptables_rules = 0
    if _which("iptables"):
        ipt_out = _run("iptables", "-L", "-n", "--line-numbers", timeout=10)
        iptables_rules = len([l for l in ipt_out.splitlines() if re.match(r"^\d+", l)])

    # SSH config
    ssh_config_path = "/etc/ssh/sshd_config"
    ssh_config = _file(ssh_config_path)
    ssh_root_login = "yes"
    ssh_password_auth = "yes"
    ssh_port = 22
    for line in ssh_config.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("permitrootlogin"):
            ssh_root_login = stripped.split(None, 1)[1] if len(stripped.split()) > 1 else "yes"
        elif stripped.startswith("passwordauthentication"):
            ssh_password_auth = stripped.split(None, 1)[1] if len(stripped.split()) > 1 else "yes"
        elif stripped.startswith("port "):
            try:
                ssh_port = int(stripped.split()[1])
            except (IndexError, ValueError):
                pass

    # sudo NOPASSWD check
    sudoers_nopasswd: list[str] = []
    for sudoers_path in [Path("/etc/sudoers")] + list(Path("/etc/sudoers.d").glob("*") if Path("/etc/sudoers.d").is_dir() else []):
        try:
            content = sudoers_path.read_text(encoding="utf-8", errors="replace")
            for line in content.splitlines():
                if "NOPASSWD" in line and not line.strip().startswith("#"):
                    sudoers_nopasswd.append(line.strip())
        except OSError:
            pass

    # Core dumps
    core_pattern = _file("/proc/sys/kernel/core_pattern")

    return {
        "aslr": aslr_value,
        "kptr_restrict": int(kptr_restrict) if kptr_restrict.isdigit() else None,
        "dmesg_restrict": int(dmesg_restrict) if dmesg_restrict.isdigit() else None,
        "apparmor_enabled": apparmor_enabled,
        "apparmor_profiles": apparmor_profiles,
        "selinux_enabled": selinux_enabled,
        "selinux_mode": selinux_mode,
        "ufw_active": ufw_active,
        "iptables_rules": iptables_rules,
        "ssh_permit_root_login": ssh_root_login,
        "ssh_password_auth": ssh_password_auth,
        "ssh_port": ssh_port,
        "sudoers_nopasswd_count": len(sudoers_nopasswd),
        "sudoers_nopasswd_entries": sudoers_nopasswd[:10],
        "core_pattern": core_pattern,
    }


# ── entry point ───────────────────────────────────────────────────────────────


def collect_linux_snapshot() -> dict[str, Any]:
    """Collect the full Linux security snapshot (all categories)."""
    return {
        "integrity": _collect_integrity(),
        "av": _collect_av(),
        "telemetry": _collect_telemetry(),
        "persistence": _collect_persistence(),
        "platform": _collect_platform(),
        "_os": "linux",
    }


if __name__ == "__main__":
    print(json.dumps(collect_linux_snapshot()))

