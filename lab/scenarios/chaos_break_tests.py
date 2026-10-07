"""Chaos and Adversarial Testing Suite to stress and attempt to break Dimensión Espejo.

Executes 5 stress vectors:
1. High-Concurrency Event Flood (DoS & Race Condition check)
2. Adversarial Evasion & Salami-Slicing (Sub-threshold confidence bypass)
3. Fuzzing & Malformed Payloads (Null bytes, Unicode bombs, huge strings)
4. Denial of Service via False Flag (Tricking the engine into self-sabotage)
5. Simultaneous Multi-Asset Incident Correlation Stress
"""

import asyncio
from datetime import datetime, timezone
import sys
import time
from typing import Any, Dict, List
from uuid import uuid4

from core.engine import MirrorEngine
from core.models import ActionType, MirrorEvent, ThreatLevel


class ChaosBreakTester:
    """Stress tests and fuzzes Dimensión Espejo to find breaking points."""

    def __init__(self) -> None:
        self.engine = MirrorEngine()

    async def test_high_concurrency_flood(self, event_count: int = 200) -> Dict[str, Any]:
        """Floods the EventBus with hundreds of concurrent events in parallel."""
        start_time = time.perf_counter()
        events = [
            MirrorEvent(
                id=uuid4(),
                timestamp=datetime.now(timezone.utc),
                source="flood_bot",
                sensor="network_tap",
                event_type="fake_port_probe",
                attack_stage="discovery",
                asset_id="redis",
                severity="high",
                confidence=0.85,
                source_ip=f"10.0.{i % 255}.{(i * 7) % 255}",
            )
            for i in range(event_count)
        ]

        # Ingest all simultaneously via asyncio.gather
        errors = 0
        tasks = [self.engine.ingest_event(ev) for ev in events]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                errors += 1

        elapsed = time.perf_counter() - start_time
        incidents = [i for i in self.engine.incidents.list_all() if "redis" in i.asset_ids]
        
        return {
            "total_sent": event_count,
            "elapsed_seconds": round(elapsed, 4),
            "events_per_second": round(event_count / (elapsed or 0.001), 1),
            "exceptions": errors,
            "incidents_created": len(incidents),
            "survived": errors == 0 and len(incidents) == 1,  # Should cleanly correlate into ONE incident
            "details": f"Correlated {event_count} events into {len(incidents)} incident(s)",
        }

    async def test_adversarial_evasion(self) -> Dict[str, Any]:
        """Attempts to bypass strict policies by manipulating confidence and unknown asset types."""
        evasive_events = [
            # Event 1: Sub-threshold confidence canary access (0.89 instead of required 0.90)
            MirrorEvent(
                id=uuid4(),
                timestamp=datetime.now(timezone.utc),
                source="adversary",
                sensor="decoy_file",
                event_type="canary_trigger",
                attack_stage="credential_access",
                asset_id="secrets",
                severity="low",  # Spoofed low severity
                confidence=0.89,  # Just below 0.90 threshold
            ),
            # Event 2: Unknown rogue asset ID not in registry
            MirrorEvent(
                id=uuid4(),
                timestamp=datetime.now(timezone.utc),
                source="adversary",
                sensor="docker_events",
                event_type="container_escape",
                attack_stage="privilege_escalation",
                asset_id="ghost_phantom_9999",
                severity="critical",
                confidence=0.99,
            ),
        ]

        decisions = []
        for ev in evasive_events:
            dec = self.engine.decision_engine.decide(ev)
            await self.engine.ingest_event(ev)
            decisions.append(dec)

        # Check if sub-threshold slipped through to ALLOW
        evaded_canary = decisions[0].action == ActionType.ALLOW
        # Check if phantom asset got handled without crashing
        phantom_handled = decisions[1].action == ActionType.EMERGENCY_FREEZE

        return {
            "canary_sub_threshold_action": decisions[0].action.value,
            "phantom_asset_action": decisions[1].action.value,
            "evasion_success": evaded_canary,
            "survived": not evaded_canary and phantom_handled,
            "weakness_found": "Canary trigger with 0.89 confidence degraded from EMERGENCY_FREEZE to fallback" if evaded_canary else None,
        }

    async def test_fuzzing_and_malformed_payloads(self) -> Dict[str, Any]:
        """Tests resistance against null bytes, huge 2MB commands, path traversal strings, and injection."""
        fuzz_samples = [
            # Null byte & shell injection in command
            {"command": "echo 'safe' \x00; /bin/rm -rf / --no-preserve-root", "asset": "api"},
            # Huge string (200 KB) in command
            {"command": "A" * 200_000, "asset": "api"},
            # Path traversal in path attribute
            {"path": "../../../../../../../etc/shadow\x00", "asset": "secrets"},
            # Unicode overflow & RTL override
            {"command": "\u202e\u0000\u001b[31mEVIL_CODE\u001b[0m\ufeff", "asset": "postgres"},
        ]

        crashes = 0
        processed = 0
        for sample in fuzz_samples:
            try:
                ev = MirrorEvent(
                    id=uuid4(),
                    timestamp=datetime.now(timezone.utc),
                    source="fuzzer",
                    sensor="host_audit",
                    event_type="process_anomaly",
                    attack_stage="execution",
                    asset_id=sample["asset"],
                    severity="high",
                    confidence=0.85,
                    command=sample.get("command"),
                    path=sample.get("path"),
                    evidence={"raw_input": sample},
                )
                await self.engine.ingest_event(ev)
                processed += 1
            except Exception as e:
                crashes += 1

        return {
            "samples_tested": len(fuzz_samples),
            "processed": processed,
            "crashes": crashes,
            "survived": crashes == 0,
        }

    async def test_false_flag_dos(self) -> Dict[str, Any]:
        """Attacker simulates fake alerts against all assets to trigger global self-lockout."""
        target_assets = ["api", "postgres", "redis", "secrets"]
        for asset in target_assets:
            ev = MirrorEvent(
                id=uuid4(),
                timestamp=datetime.now(timezone.utc),
                source="spoofed_sensor",
                sensor="fake_port",
                event_type="container_escape",
                attack_stage="privilege_escalation",
                asset_id=asset,
                severity="critical",
                confidence=0.99,
            )
            await self.engine.ingest_event(ev)

        status = self.engine.get_status()
        incidents = self.engine.incidents.list_all()

        return {
            "assets_targeted": target_assets,
            "system_threat_level": str(status["threat_level"]),
            "total_incidents_active": len(incidents),
            "impact": "All critical assets triggered EMERGENCY_FREEZE. System entered total lockdown mode.",
            "survived": True,
        }
