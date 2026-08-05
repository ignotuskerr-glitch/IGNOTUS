from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    from core.red_mode.platform import IS_WINDOWS, IS_WSL
except ImportError:
    # Standalone / remote fallback
    import os
    IS_WINDOWS = os.name == "nt"
    try:
        IS_WSL = not IS_WINDOWS and Path("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
    except OSError:
        IS_WSL = False

# Windows-only imports — loaded lazily to avoid ImportError on Linux/WSL
if IS_WINDOWS:
    import multiprocessing.connection
    import winreg
    try:
        from core.red_mode.powershell import PROJECT_ROOT, _run_script
    except ImportError:
        pass


def _result(status: str, detail: str, **evidence) -> dict:
    return {"status": status, "detail": detail, "evidence": evidence}


# ── Canário 1: processo Python ─────────────────────────────────────────────────

def _process_canary(marker: str) -> dict:
    completed = subprocess.run(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", marker],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    ok = completed.returncode == 0 and marker in completed.stdout
    return _result(
        "PASS" if ok else "FAIL", f"exit={completed.returncode}; marker={ok}"
    )


# ── Canário 2: shell (PowerShell no Windows, bash no Linux) ──────────────────

def _shell_canary(marker: str) -> dict:
    if IS_WINDOWS or IS_WSL:
        script = f"$marker='{marker}'; Write-Output $marker; Get-CimInstance Win32_OperatingSystem | Out-Null"
        cmd = [
            "powershell.exe",
            "-NoLogo", "-NoProfile", "-NonInteractive",
            "-Command", script,
        ]
    else:
        cmd = ["bash", "-c", f"echo '{marker}'"]
    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    ok = completed.returncode == 0 and marker in completed.stdout
    return _result(
        "PASS" if ok else "FAIL", f"exit={completed.returncode}; marker={ok}"
    )


# ── Canário 3: arquivo temporário ─────────────────────────────────────────────

def _file_canary(marker: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="ignotus-red-") as directory:
        path = Path(directory) / f"{marker}.txt"
        path.write_text(marker, encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        verified = path.read_text(encoding="utf-8") == marker
    removed = not path.exists()
    return _result(
        "PASS" if verified and removed else "FAIL",
        f"verified={verified}; removed={removed}",
        sha256=digest,
    )


# ── Canário 4: registry (Windows) / xattr em arquivo (Linux) ─────────────────

def _registry_canary(marker: str) -> dict:
    if IS_WINDOWS:
        key_path = rf"Software\Ignotus\RedMode\{marker}"
        created = False
        verified = False
        removed = False
        try:
            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE
            ) as key:
                winreg.SetValueEx(key, "Canary", 0, winreg.REG_SZ, marker)
                created = True
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ
            ) as key:
                verified = winreg.QueryValueEx(key, "Canary")[0] == marker
        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
                removed = True
                for parent in (r"Software\Ignotus\RedMode", r"Software\Ignotus"):
                    try:
                        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, parent)
                    except OSError:
                        pass
            except OSError:
                removed = False
        ok = created and verified and removed
        return _result(
            "PASS" if ok else "FAIL",
            f"created={created}; verified={verified}; removed={removed}",
        )
    else:
        # Linux: simulate a "persistent metadata" write using extended attributes
        # on a temp file. Falls back to a plain key=value file if xattr unavailable.
        with tempfile.NamedTemporaryFile(prefix="ignotus-red-reg-", delete=False) as tf:
            tmp = Path(tf.name)
        try:
            created = False
            verified = False
            try:
                import os
                tmp.write_text(marker, encoding="utf-8")
                os.setxattr(str(tmp), "user.ignotus_canary", marker.encode())
                read_back = os.getxattr(str(tmp), "user.ignotus_canary").decode()
                created = True
                verified = read_back == marker
            except (OSError, AttributeError):
                # xattr not supported (e.g. tmpfs) — plain file fallback
                tmp.write_text(marker, encoding="utf-8")
                created = True
                verified = tmp.read_text(encoding="utf-8") == marker
            tmp.unlink(missing_ok=True)
            removed = not tmp.exists()
        except OSError:
            tmp.unlink(missing_ok=True)
            removed = not tmp.exists()
            return _result("FAIL", "linux_metadata_write_error")
        ok = created and verified and removed
        return _result(
            "PASS" if ok else "FAIL",
            f"created={created}; verified={verified}; removed={removed}; backend=xattr_or_file",
        )


# ── Canário 5: TCP loopback ────────────────────────────────────────────────────

def _tcp_canary(marker: str) -> dict:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        connection, _ = listener.accept()
        with connection:
            connection.sendall(marker.encode())
        listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
        verified = client.recv(256).decode() == marker
    thread.join(timeout=5)
    return _result(
        "PASS" if verified else "FAIL", f"loopback=true; marker={verified}", port=port
    )


# ── Canário 6: pipe nomeado (AF_PIPE Windows / AF_UNIX Linux) ────────────────

def _named_pipe_canary(marker: str) -> dict:
    if IS_WINDOWS:
        address = rf"\\.\pipe\ignotus-red-{uuid.uuid4().hex}"
        listener = multiprocessing.connection.Listener(address, family="AF_PIPE")
        received: dict = {"value": ""}

        def serve():
            connection = listener.accept()
            try:
                received["value"] = connection.recv()
                connection.send(marker)
            finally:
                connection.close()
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        client = multiprocessing.connection.Client(address, family="AF_PIPE")
        try:
            client.send(marker)
            response = client.recv()
        finally:
            client.close()
        thread.join(timeout=5)
        verified = response == marker and received["value"] == marker
    else:
        # Linux: Unix domain socket (SOCK_STREAM)
        import os as _os
        sock_path = f"/tmp/ignotus-red-{uuid.uuid4().hex}.sock"
        received_linux: dict = {"value": b""}

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(sock_path)
        server.listen(1)

        def serve_unix():
            conn, _ = server.accept()
            with conn:
                received_linux["value"] = conn.recv(256)
                conn.sendall(marker.encode())
            server.close()

        thread = threading.Thread(target=serve_unix, daemon=True)
        thread.start()
        client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_sock.connect(sock_path)
        try:
            client_sock.sendall(marker.encode())
            response = client_sock.recv(256).decode()
        finally:
            client_sock.close()
        thread.join(timeout=5)
        try:
            _os.unlink(sock_path)
        except OSError:
            pass
        verified = response == marker and received_linux["value"].decode() == marker

    return _result(
        "PASS" if verified else "FAIL", f"named_pipe=true; marker={verified}"
    )


# ── Canário 7: tentativa de dumping de credenciais (T1003) ───────────────────

def _credential_dump_canary(marker: str) -> dict:
    if IS_WINDOWS:
        import ctypes
        # Encontra o PID do lsass.exe usando tasklist
        completed = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq lsass.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, check=False
        )
        pid = None
        for line in completed.stdout.splitlines():
            if "lsass.exe" in line.lower():
                parts = line.split(",")
                if len(parts) > 1:
                    pid = int(parts[1].strip('"'))
                    break
        if not pid:
            return _result("FAIL", "lsass_pid_not_found")
        # 0x0400 = PROCESS_QUERY_INFORMATION (tentativa de abrir o handle)
        handle = ctypes.windll.kernel32.OpenProcess(0x0400, False, pid)
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return _result("PASS", "lsass_handle_opened_warning", pid=pid)
        else:
            err = ctypes.windll.kernel32.GetLastError()
            return _result("PASS", f"lsass_access_denied_expected (error={err})", pid=pid)
    else:
        # Linux: tenta ler o arquivo /etc/shadow
        try:
            with open("/etc/shadow", "r") as f:
                content = f.read(50)
            return _result("PASS", "read_shadow_success_root_warning", content_preview=content[:20])
        except PermissionError as exc:
            return _result("PASS", f"expected_permission_denied: {exc}")
        except OSError as exc:
            return _result("FAIL", f"unexpected_os_error: {exc}")


# ── Canário 8: simulação de persistência (T1053/T1098) ──────────────────────

def _persistence_simulation_canary(marker: str) -> dict:
    if IS_WINDOWS:
        task_name = f"Ignotus_Canary_Task_{marker[:8]}"
        create_cmd = [
            "schtasks.exe", "/Create", "/TN", task_name,
            "/TR", "cmd.exe /c echo ignotus", "/SC", "ONCE",
            "/ST", "00:00", "/F"
        ]
        delete_cmd = ["schtasks.exe", "/Delete", "/TN", task_name, "/F"]
        created = subprocess.run(create_cmd, capture_output=True, text=True, check=False)
        deleted = subprocess.run(delete_cmd, capture_output=True, text=True, check=False)
        ok = created.returncode == 0 and deleted.returncode == 0
        return _result(
            "PASS" if ok else "FAIL",
            f"schtasks_created={created.returncode == 0}; deleted={deleted.returncode == 0}",
        )
    else:
        # Linux: modifica ~/.ssh/authorized_keys
        auth_keys_path = Path.home() / ".ssh" / "authorized_keys"
        try:
            auth_keys_path.parent.mkdir(parents=True, exist_ok=True)
            canary_line = f"# IGNOTUS_PERSISTENCE_CANARY_{marker}"
            existed = auth_keys_path.exists()
            content = auth_keys_path.read_text(encoding="utf-8") if existed else ""
            
            # Append canary key line
            auth_keys_path.write_text(content + f"\n{canary_line}\n", encoding="utf-8")
            written = canary_line in auth_keys_path.read_text(encoding="utf-8")
            
            # Remove canary key line
            clean = auth_keys_path.read_text(encoding="utf-8").replace(canary_line, "").strip()
            if clean:
                auth_keys_path.write_text(clean, encoding="utf-8")
            else:
                auth_keys_path.write_text("", encoding="utf-8")
                if not existed:
                    auth_keys_path.unlink(missing_ok=True)
            ok = written and (canary_line not in auth_keys_path.read_text(encoding="utf-8") if auth_keys_path.exists() else True)
            return _result("PASS" if ok else "FAIL", f"ssh_authorized_keys_simulated={ok}")
        except OSError as exc:
            return _result("FAIL", f"ssh_authorized_keys_error: {exc}")



# ── Event checks (Windows: PowerShell / Linux: journalctl) ────────────────────

def _event_checks_windows(marker: str, start: str, tcp_port: int = 0) -> list[dict]:
    output = _run_script(
        PROJECT_ROOT / "scripts" / "red_mode_event_check.ps1",
        "-Marker", marker,
        "-StartUtc", start,
        "-TcpPort", str(tcp_port),
        timeout=60,
    )
    payload = json.loads(output)
    return payload if isinstance(payload, list) else [payload]


def _event_checks_linux(marker: str, start: str) -> list[dict]:
    """Check if the canary marker appeared in journald / syslog."""
    results: list[dict] = []
    # journalctl search
    try:
        out = subprocess.run(
            ["journalctl", "--since", start[:19].replace("T", " "), "--no-pager",
             "--grep", marker, "-q"],
            capture_output=True, text=True, check=False, timeout=15
        )
        observed = out.returncode == 0 and marker in out.stdout
        results.append({
            "log": "journald",
            "signal": "journald_search",
            "observed": observed,
            "accessible": True,
            "enabled": True,
        })
    except (OSError, subprocess.TimeoutExpired):
        results.append({
            "log": "journald",
            "signal": "journald_search",
            "observed": False,
            "accessible": False,
            "enabled": False,
            "error": "journalctl unavailable",
        })
    # syslog search (fallback)
    for log_path in ("/var/log/syslog", "/var/log/messages"):
        p = Path(log_path)
        if not p.exists():
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            observed = marker in content
            results.append({
                "log": log_path,
                "signal": "syslog_search",
                "observed": observed,
                "accessible": True,
                "enabled": True,
            })
        except OSError:
            results.append({
                "log": log_path,
                "signal": "syslog_search",
                "observed": False,
                "accessible": False,
                "enabled": False,
            })
        break  # one syslog check is enough
    return results


# ── Public entry point ────────────────────────────────────────────────────────

def run_canaries() -> dict:
    marker = "IGNOTUS_RED_" + uuid.uuid4().hex.upper()
    started_at = datetime.now(timezone.utc).isoformat()
    actions: dict = {}

    runners = {
        "process": _process_canary,
        "shell": _shell_canary,
        "file": _file_canary,
        "registry": _registry_canary,
        "tcp_loopback": _tcp_canary,
        "named_pipe": _named_pipe_canary,
        "credential_dump": _credential_dump_canary,
        "persistence_sim": _persistence_simulation_canary,
    }
    for name, runner in runners.items():
        try:
            actions[name] = runner(marker)
        except (
            OSError, ValueError, RuntimeError,
            subprocess.SubprocessError, EOFError,
        ) as exc:
            actions[name] = _result("FAIL", f"{type(exc).__name__}: {exc}")

    time.sleep(1)

    try:
        tcp_port = int(
            actions.get("tcp_loopback", {}).get("evidence", {}).get("port", 0)
        )
        if IS_WINDOWS or IS_WSL:
            events = _event_checks_windows(marker, started_at, tcp_port)
        else:
            events = _event_checks_linux(marker, started_at)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        events = [{"accessible": False, "observed": False,
                   "error": f"{type(exc).__name__}: {exc}"}]

    return {
        "marker": marker,
        "started_at": started_at,
        "actions": actions,
        "events": events,
        "cleanup": "temporary file, sockets and pipe removed",
    }


if __name__ == "__main__":
    print(json.dumps(run_canaries()))

