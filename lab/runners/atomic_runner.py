import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime, timezone
import yaml

from core.models import MirrorEvent

logger = logging.getLogger("mirror.atomic")


class AtomicRedTeamRunner:
    """Loads and executes attack techniques from the cloned Atomic Red Team repository."""

    def __init__(self, atomics_dir: Optional[Path] = None) -> None:
        if atomics_dir:
            self.atomics_dir = atomics_dir
        else:
            local_atomics = Path(__file__).resolve().parent.parent / "atomics"
            repo_atomics = (
                Path(__file__).resolve().parent.parent.parent
                / "repos"
                / "atomic-red-team"
                / "atomics"
            )
            self.atomics_dir = local_atomics if local_atomics.exists() else repo_atomics

    def list_techniques(self) -> List[str]:
        """List all available technique IDs in the atomics directory."""
        if not self.atomics_dir.exists():
            return []
        return sorted([d.name for d in self.atomics_dir.iterdir() if d.is_dir() and d.name.startswith("T")])

    def load_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Load technique definition YAML from the cloned repository."""
        tech_file = self.atomics_dir / technique_id / f"{technique_id}.yaml"
        if not tech_file.exists():
            logger.warning("Technique file %s not found", tech_file)
            return None

        with open(tech_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def create_event_from_technique(
        self,
        technique_id: str,
        test_index: int = 0,
        asset_id: str = "secrets",
    ) -> Optional[MirrorEvent]:
        """Transform a real Atomic Red Team test definition into a normalized MirrorEvent."""
        data = self.load_technique(technique_id)
        if not data or "atomic_tests" not in data:
            return None

        tests = data["atomic_tests"]
        if test_index >= len(tests):
            test_index = 0

        test = tests[test_index]
        name = test.get("name", "Unknown test")
        executor = test.get("executor", {})
        command = executor.get("command", "").strip()

        # Map MITRE attack stage
        attack_stage = "credential_access" if "T1552" in technique_id else "defense_evasion"

        return MirrorEvent(
            id=uuid4(),
            timestamp=datetime.now(timezone.utc),
            source="atomic_red_team",
            sensor="host_audit",
            event_type="canary_trigger" if "T1552" in technique_id else "process_anomaly",
            attack_stage=attack_stage,
            asset_id=asset_id,
            severity="critical" if "T1552" in technique_id else "high",
            confidence=0.96,
            command=command[:200] if command else None,
            evidence={
                "technique_id": technique_id,
                "display_name": data.get("display_name"),
                "test_name": name,
                "supported_platforms": test.get("supported_platforms", []),
            },
        )
