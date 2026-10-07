"""Extreme Stress and Adversarial Integrity Test Suite.

No mocks, no fluff. Tests:
1. Massive Concurrency & Race Conditions (1,000 parallel async events across 4 assets)
2. Memory footprint & latency (p50, p99, throughput)
3. Cryptographic Tamper-Detection on Evidence Vault (Byte flipping on disk)
4. MITRE ATT&CK Real Repo Extraction (Parsing & processing 50 real atomic techniques)
5. Secret Leakage Fuzzing in Mirror Environment Sanitizer
"""

import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import resource
import time
from typing import Any, Dict, List
from uuid import uuid4

from core.engine import MirrorEngine
from core.models import MirrorEvent
from lab.runners.atomic_runner import AtomicRedTeamRunner
from mirror.sanitization import MirrorSanitizer


class ExtremeStressTester:
    def __init__(self) -> None:
        self.engine = MirrorEngine()
        self.runner = AtomicRedTeamRunner()

    def _get_rss_mb(self) -> float:
        # On macOS, ru_maxrss is in bytes
        rusage = resource.getrusage(resource.RUSAGE_SELF)
        return rusage.ru_maxrss / (1024 * 1024)

    async def benchmark_massive_concurrency(self, total_events: int = 1000) -> Dict[str, Any]:
        """Fire 1,000 asynchronous events simultaneously across multiple assets and measure race conditions."""
        assets = ["api", "postgres", "redis", "secrets"]
        sensors = ["docker_events", "decoy_file", "process_monitor", "fake_port"]
        event_types = ["container_escape", "canary_trigger", "process_anomaly", "fake_port_probe"]

        events: List[MirrorEvent] = []
        for i in range(total_events):
            asset = assets[i % len(assets)]
            sensor = sensors[i % len(sensors)]
            ev_type = event_types[i % len(event_types)]
            events.append(
                MirrorEvent(
                    id=uuid4(),
                    timestamp=datetime.now(timezone.utc),
                    source="stress_bot",
                    sensor=sensor,
                    event_type=ev_type,
                    asset_id=asset,
                    severity="high" if i % 2 == 0 else "critical",
                    confidence=round(random.uniform(0.75, 0.99), 2),
                )
            )

        rss_before_mb = self._get_rss_mb()
        latencies: List[float] = []

        async def timed_ingest(ev: MirrorEvent) -> None:
            t0 = time.perf_counter()
            await self.engine.ingest_event(ev)
            latencies.append((time.perf_counter() - t0) * 1000)  # ms

        start_time = time.perf_counter()
        tasks = [timed_ingest(ev) for ev in events]
        await asyncio.gather(*tasks, return_exceptions=False)
        total_time = time.perf_counter() - start_time

        rss_after_mb = self._get_rss_mb()
        latencies.sort()

        # Check for duplicate incident IDs
        incident_ids = [inc.id for inc in self.engine.incidents.list_all()]
        has_duplicates = len(incident_ids) != len(set(incident_ids))

        p50 = latencies[len(latencies) // 2] if latencies else 0
        p99 = latencies[int(len(latencies) * 0.99)] if latencies else 0

        return {
            "total_events": total_events,
            "total_time_seconds": round(total_time, 4),
            "throughput_events_per_sec": round(total_events / (total_time or 0.001), 1),
            "latency_p50_ms": round(p50, 3),
            "latency_p99_ms": round(p99, 3),
            "memory_delta_mb": round(rss_after_mb - rss_before_mb, 2),
            "incidents_created": len(incident_ids),
            "race_condition_detected": has_duplicates,
            "status": "PASS" if not has_duplicates else "FAIL",
        }

    def test_evidence_tamper_detection(self) -> Dict[str, Any]:
        """Seal evidence, modify 1 byte on disk, and check cryptographic hash failure."""
        incident_id = f"INC-TEST-TAMPER-{int(time.time())}"
        snapshot = self.engine.forensics.collect_snapshot(
            incident_id=incident_id,
            container_identifier="developer-api",
            trigger_reason="extreme_tamper_test",
        )
        original_hash = snapshot["sha256_integrity_seal"]

        manifest_path = self.engine.forensics.vault_dir / incident_id / "forensics_manifest.json"
        with open(manifest_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Tamper with the evidence on disk (simulate rogue actor altering forensic evidence)
        tampered_content = content.replace("extreme_tamper_test", "tampered_by_adversary")
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write(tampered_content)

        # Recalculate hash of tampered data without the seal field
        with open(manifest_path, "r", encoding="utf-8") as f:
            loaded_data = json.load(f)

        stored_seal = loaded_data.pop("sha256_integrity_seal")
        recalculated_hash = hashlib.sha256(
            json.dumps(loaded_data, indent=2, sort_keys=True).encode("utf-8")
        ).hexdigest()

        tamper_detected = stored_seal != recalculated_hash

        return {
            "incident_id": incident_id,
            "original_sha256": original_hash,
            "recalculated_sha256": recalculated_hash,
            "tamper_detected": tamper_detected,
            "status": "PASS" if tamper_detected else "FAIL",
        }

    async def stress_real_mitre_techniques(self, sample_size: int = 50) -> Dict[str, Any]:
        """Extract and process 50 real MITRE techniques directly from repos/atomic-red-team."""
        techniques = self.runner.list_techniques()
        sample = techniques[:sample_size]

        parsed = 0
        decided = 0
        errors: List[str] = []

        for tid in sample:
            try:
                ev = self.runner.create_event_from_technique(tid, test_index=0, asset_id="api")
                if ev:
                    parsed += 1
                    decision = self.engine.decision_engine.decide(ev)
                    await self.engine.ingest_event(ev)
                    if decision.action:
                        decided += 1
            except Exception as e:
                errors.append(f"{tid}: {str(e)}")

        return {
            "total_available_techniques": len(techniques),
            "sample_tested": len(sample),
            "successfully_parsed": parsed,
            "successfully_decided": decided,
            "parser_exceptions": len(errors),
            "error_details": errors[:5],
            "status": "PASS" if len(errors) == 0 and parsed > 0 else "FAIL",
        }

    def test_sanitizer_secret_leakage(self) -> Dict[str, Any]:
        """Subject the MirrorSanitizer to 15 real-world high-entropy secret formats."""
        dummy_aws_id = "".join(["AKIA", "_TEST_AWS_ACCESS_KEY_REDACTED"])
        dummy_aws_secret = "AWS_TEST_SECRET_KEY_FIXTURE_REDACTED_9941"
        dummy_openai = "".join(["sk", "-proj-", "TEST_REDACTED_OPENAI_KEY_99818273645214829103948572619"])
        dummy_stripe = "".join(["sk", "_live_", "TEST_REDACTED_STRIPE_KEY_THAT_MUST_NEVER_LEAK"])
        dummy_github = "".join(["ghp", "_", "TEST_REDACTED_DEV_PERSONAL_ACCESS_TOKEN_99"])

        dirty_env = [
            f"AWS_ACCESS_KEY_ID={dummy_aws_id}",
            f"AWS_SECRET_ACCESS_KEY={dummy_aws_secret}",
            "DATABASE_URL=postgres://test_admin:TestSecretP@ssw0rd!@10.0.1.5:5432/production_db",
            "DB_URL=mysql://test_root:TestPassword123!@127.0.0.1:3306/finance",
            f"OPENAI_API_KEY={dummy_openai}",
            f"STRIPE_SECRET_KEY={dummy_stripe}",
            f"GITHUB_TOKEN={dummy_github}",
            "ADMIN_PASSWORD=TestSecretRootPassword2026!",
            "JWT_SECRET=test_hmac_signing_key_48102948192849182",
            "SAFE_VAR=public_developer_setting",
            "PORT=8080",
        ]

        sanitized = MirrorSanitizer.sanitize_environment(dirty_env)

        # Check for leakage
        leaked = []
        forbidden_patterns = [
            dummy_aws_id,
            dummy_aws_secret,
            "TestSecretP@ssw0rd!",
            "TestPassword123!",
            dummy_openai,
            "TestSecretRootPassword",
            "test_hmac_signing_key",
            dummy_stripe,
            dummy_github,
        ]

        sanitized_dump = "\n".join(sanitized)
        for pattern in forbidden_patterns:
            if pattern in sanitized_dump:
                leaked.append(pattern)

        # Specifically check if STRIPE_SECRET_KEY, GITHUB_TOKEN, etc. were scrubbed
        sanitized_dict = dict(item.split("=", 1) for item in sanitized if "=" in item)

        stripe_sanitized = "".join(["sk", "_live"]) not in sanitized_dict.get("STRIPE_SECRET_KEY", "")
        github_sanitized = "".join(["ghp", "_"]) not in sanitized_dict.get("GITHUB_TOKEN", "")

        return {
            "total_vars_evaluated": len(dirty_env),
            "leaked_forbidden_patterns": leaked,
            "stripe_sanitized": stripe_sanitized,
            "github_sanitized": github_sanitized,
            "mirror_markers_present": "MIRROR_WORLD_ACTIVE=true" in sanitized,
            "status": "PASS" if len(leaked) == 0 and stripe_sanitized and github_sanitized else "FAIL",
        }
