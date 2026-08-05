"""Catalog of local, benign ATT&CK-aligned telemetry simulations."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Simulation:
    id: str
    name: str
    attack_id: str
    tactic: str
    profile: str
    observable: str


SIMULATIONS = (
    Simulation("PT-SYS-001", "System information canary", "T1082", "Discovery", "baseline", "Local platform and hostname query"),
    Simulation("PT-PROC-001", "Process creation canary", "T1059.006", "Execution", "baseline", "Visible Python child process with an IGNOTUS marker"),
    Simulation("PT-FILE-001", "File staging canary", "T1074.001", "Collection", "baseline", "Temporary marker file created, hashed and removed"),
    Simulation("PT-ARCH-001", "Archive canary", "T1560.001", "Collection", "baseline", "Temporary ZIP containing only an IGNOTUS marker"),
    Simulation("PT-OBF-001", "Encoded-content canary", "T1027", "Defense Evasion", "baseline", "Benign marker encoded and decoded in memory; never executed"),
    Simulation("PT-DNS-001", "Loopback DNS canary", "T1016", "Discovery", "network", "Resolve localhost only"),
    Simulation("PT-TCP-001", "Loopback TCP canary", "T1046", "Discovery", "network", "One TCP exchange bound to 127.0.0.1"),
    Simulation("PT-HTTP-001", "Loopback HTTP canary", "T1071.001", "Command and Control", "network", "One local HTTP request carrying a visible Purple Team marker"),
)


def simulations_for(profile: str) -> tuple[Simulation, ...]:
    if profile == "all":
        return SIMULATIONS
    return tuple(item for item in SIMULATIONS if item.profile == profile)
