"""Execute safe local simulations and generate coverage reports."""

from __future__ import annotations

import base64
import hashlib
import json
import platform
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

from core.purple_team.catalog import Simulation, simulations_for
from core.detection_policy import validate_detection_policy

MARKER = "IGNOTUS_PURPLE_TEAM_CANARY"
VALIDATED_STATES = {"detected", "validated", "covered"}


@dataclass
class PurpleResult:
    simulation_id: str
    name: str
    attack_id: str
    tactic: str
    observable: str
    execution: str
    detection: str
    rule_id: str | None
    duration_ms: int
    evidence: str


@dataclass
class PurpleRun:
    profile: str
    started_at: str
    safety_mode: str
    results: list[PurpleResult]
    json_path: str = ""
    markdown_path: str = ""

    @property
    def passed(self) -> int:
        return sum(item.execution == "passed" for item in self.results)

    @property
    def covered(self) -> int:
        return sum(item.detection == "validated" for item in self.results)


class _CanaryHandler(BaseHTTPRequestHandler):
    marker_seen = False

    def do_GET(self):
        type(self).marker_seen = self.headers.get("X-Ignotus-Canary") == MARKER
        body = MARKER.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *args):
        return


def _system_canary() -> str:
    return f"host={socket.gethostname()} platform={platform.system()} {platform.release()}"


def _process_canary() -> str:
    completed = subprocess.run(
        [sys.executable, "-c", f"print('{MARKER}')"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    return f"child_exit={completed.returncode} marker={MARKER in completed.stdout}"


def _file_canary() -> str:
    with tempfile.TemporaryDirectory(prefix="ignotus-purple-") as directory:
        path = Path(directory) / "canary.txt"
        path.write_text(MARKER, encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"temporary_file_removed={not path.exists()} sha256={digest}"


def _archive_canary() -> str:
    with tempfile.TemporaryDirectory(prefix="ignotus-purple-") as directory:
        archive = Path(directory) / "canary.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr("canary.txt", MARKER)
        with zipfile.ZipFile(archive) as bundle:
            verified = bundle.read("canary.txt").decode() == MARKER
    return f"archive_verified={verified} temporary_archive_removed={not archive.exists()}"


def _encoded_canary() -> str:
    encoded = base64.b64encode(MARKER.encode())
    verified = base64.b64decode(encoded).decode() == MARKER
    return f"decoded_marker={verified} executed=false"


def _dns_canary() -> str:
    addresses = sorted({item[4][0] for item in socket.getaddrinfo("localhost", 0)})
    return "localhost=" + ",".join(addresses)


def _tcp_canary() -> str:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        connection, _ = listener.accept()
        with connection:
            connection.sendall(MARKER.encode())
        listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
        verified = client.recv(128).decode() == MARKER
    thread.join(timeout=3)
    return f"loopback=127.0.0.1 ephemeral_port={port} marker={verified}"


def _http_canary() -> str:
    _CanaryHandler.marker_seen = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CanaryHandler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    request = Request(
        f"http://127.0.0.1:{server.server_port}/purple-canary",
        headers={"X-Ignotus-Canary": MARKER},
    )
    with urlopen(request, timeout=3) as response:
        verified = response.read().decode() == MARKER
    thread.join(timeout=3)
    server.server_close()
    return f"loopback_http=true response_marker={verified} header_seen={_CanaryHandler.marker_seen}"


RUNNERS = {
    "PT-SYS-001": _system_canary,
    "PT-PROC-001": _process_canary,
    "PT-FILE-001": _file_canary,
    "PT-ARCH-001": _archive_canary,
    "PT-OBF-001": _encoded_canary,
    "PT-DNS-001": _dns_canary,
    "PT-TCP-001": _tcp_canary,
    "PT-HTTP-001": _http_canary,
}


def _load_detections(path: str | None) -> dict:
    if not path:
        return {}
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return validate_detection_policy(payload).get("detections", {})


def _execute(simulation: Simulation, detections: dict) -> PurpleResult:
    start = time.perf_counter()
    try:
        evidence = RUNNERS[simulation.id]()
        execution = "passed"
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        execution = "failed"
        evidence = f"{type(exc).__name__}: {exc}"
    duration_ms = round((time.perf_counter() - start) * 1000)
    mapping = detections.get(simulation.id, {})
    state = str(mapping.get("status", "not_configured")).casefold()
    detection = "validated" if state in VALIDATED_STATES else state
    return PurpleResult(
        simulation.id,
        simulation.name,
        simulation.attack_id,
        simulation.tactic,
        simulation.observable,
        execution,
        detection,
        mapping.get("rule_id"),
        duration_ms,
        evidence,
    )


def _write_reports(run: PurpleRun, output_dir: str) -> None:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = destination / f"purple_{run.profile}_{timestamp}.json"
    markdown_path = destination / f"purple_{run.profile}_{timestamp}.md"
    payload = {
        "schema_version": 1,
        "profile": run.profile,
        "started_at": run.started_at,
        "safety_mode": run.safety_mode,
        "summary": {
            "total": len(run.results),
            "executed": run.passed,
            "detection_validated": run.covered,
            "coverage_gaps": len(run.results) - run.covered,
        },
        "results": [asdict(item) for item in run.results],
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# Ignotus Purple Team Report", "", f"- Profile: `{run.profile}`",
        f"- Started: `{run.started_at}`", f"- Safety: {run.safety_mode}",
        f"- Simulations passed: {run.passed}/{len(run.results)}",
        f"- Detection coverage validated: {run.covered}/{len(run.results)}", "",
        "| Simulation | ATT&CK | Execution | Detection | Rule |",
        "|---|---|---|---|---|",
    ]
    for item in run.results:
        lines.append(
            f"| {item.simulation_id} | {item.attack_id} | {item.execution} | "
            f"{item.detection} | {item.rule_id or '—'} |"
        )
    lines.extend(["", "All actions were local, visible, benign, and automatically cleaned up."])
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    run.json_path = str(json_path.resolve())
    run.markdown_path = str(markdown_path.resolve())


def run_purple_team(profile="baseline", detections_file=None, output_dir="output/purple") -> PurpleRun:
    detections = _load_detections(detections_file)
    run = PurpleRun(
        profile=profile,
        started_at=datetime.now(timezone.utc).isoformat(),
        safety_mode="local-only; benign canaries; no evasion, persistence, or remote execution",
        results=[_execute(item, detections) for item in simulations_for(profile)],
    )
    _write_reports(run, output_dir)
    return run
