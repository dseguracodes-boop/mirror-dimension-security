from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import docker
from docker.errors import DockerException, NotFound

import re
import time

logger = logging.getLogger("mirror.evidence.forensics")


class ForensicsCollector:
    """Captures and cryptographically seals forensic snapshots of compromised containers."""

    def __init__(
        self,
        vault_dir: Optional[Path] = None,
        client: Optional[docker.DockerClient] = None,
        debounce_seconds: float = 2.0,
    ) -> None:
        self.vault_dir = vault_dir or (Path(__file__).resolve().parent.parent / "evidence_vault")
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.debounce_seconds = debounce_seconds
        self._cached_snapshots: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        try:
            self.client = client or docker.from_env()
        except DockerException:
            self.client = None

    def _sanitize_incident_id(self, incident_id: str) -> str:
        """Prevent path traversal and malicious filenames in incident directory creation."""
        clean_id = re.sub(r"[^A-Za-z0-9_\-\.]", "_", incident_id)
        if ".." in clean_id or not clean_id.strip():
            clean_id = clean_id.replace("..", "_") or "INC_SANITIZED"
        return clean_id

    def collect_snapshot(
        self,
        incident_id: str,
        container_identifier: str,
        trigger_reason: str = "security_policy_enforcement",
    ) -> Optional[Dict[str, Any]]:
        """Collect filesystem diff, inspection details, and write a signed evidence manifest."""
        safe_incident_id = self._sanitize_incident_id(incident_id)
        now_ts = time.time()

        # Check debounce cache to prevent disk thrashing during DoS floods
        if safe_incident_id in self._cached_snapshots:
            last_ts, cached = self._cached_snapshots[safe_incident_id]
            if (now_ts - last_ts) < self.debounce_seconds:
                logger.debug(
                    "Forensic debouncing active for %s: skipping duplicate disk write.",
                    safe_incident_id,
                )
                return cached

        incident_dir = self.vault_dir / safe_incident_id
        incident_dir.mkdir(parents=True, exist_ok=True)

        snapshot_data: Dict[str, Any] = {
            "incident_id": safe_incident_id,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "target": container_identifier,
            "trigger_reason": trigger_reason,
            "filesystem_diff": [],
            "inspection": {},
        }

        if self.client:
            try:
                container = self.client.containers.get(container_identifier)
                # 1. Capture filesystem modifications (files modified/added/deleted by attacker)
                try:
                    diff_list = container.diff()
                    # Docker diff format: [{'Path': '/tmp/evil.sh', 'Kind': 0 (C), 1 (A), 2 (D)}]
                    kind_map = {0: "MODIFIED", 1: "ADDED", 2: "DELETED"}
                    snapshot_data["filesystem_diff"] = [
                        {"path": item.get("Path"), "action": kind_map.get(item.get("Kind"), "UNKNOWN")}
                        for item in (diff_list or [])
                    ]
                except Exception as e:
                    logger.warning("Could not collect filesystem diff for %s: %s", container_identifier, e)

                # 2. Capture container inspection
                try:
                    attrs = container.attrs
                    snapshot_data["inspection"] = {
                        "id": attrs.get("Id"),
                        "name": attrs.get("Name"),
                        "created": attrs.get("Created"),
                        "image": attrs.get("Config", {}).get("Image"),
                        "cmd": attrs.get("Config", {}).get("Cmd"),
                        "env": [
                            var.split("=")[0] + "=***REDACTED***" if "KEY" in var or "PASS" in var or "SECRET" in var else var
                            for var in attrs.get("Config", {}).get("Env", [])
                        ],
                        "state": attrs.get("State"),
                    }
                except Exception as e:
                    logger.warning("Could not collect attrs for %s: %s", container_identifier, e)

            except NotFound:
                logger.error("Container %s not found for forensic snapshot", container_identifier)
                snapshot_data["error"] = "container_not_found"
            except Exception as e:
                logger.error("Error collecting forensic data: %s", e)
                snapshot_data["error"] = str(e)

        # 3. Cryptographically seal manifest with SHA-256
        raw_json = json.dumps(snapshot_data, indent=2, sort_keys=True)
        sha256_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
        snapshot_data["sha256_integrity_seal"] = sha256_hash

        manifest_path = incident_dir / "forensics_manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(snapshot_data, f, indent=2)

        logger.critical(
            "FORENSIC EVIDENCE SEALED: %s [SHA-256: %s...]",
            manifest_path,
            sha256_hash[:16],
        )

        self._cached_snapshots[safe_incident_id] = (now_ts, snapshot_data)
        return snapshot_data

    def verify_manifest(self, incident_id: str) -> Dict[str, Any]:
        """Verify the cryptographic SHA-256 seal of an existing incident manifest on disk."""
        safe_id = self._sanitize_incident_id(incident_id)
        manifest_path = self.vault_dir / safe_id / "forensics_manifest.json"

        if not manifest_path.exists():
            return {
                "incident_id": safe_id,
                "verified": False,
                "error": "manifest_not_found",
                "manifest_path": str(manifest_path),
            }

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if "sha256_integrity_seal" not in data:
                return {
                    "incident_id": safe_id,
                    "verified": False,
                    "error": "missing_seal",
                }

            stored_seal = data.pop("sha256_integrity_seal")
            recalculated_hash = hashlib.sha256(
                json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
            ).hexdigest()

            import hmac
            is_valid = hmac.compare_digest(stored_seal, recalculated_hash)
            return {
                "incident_id": safe_id,
                "verified": is_valid,
                "stored_seal": stored_seal,
                "calculated_hash": recalculated_hash,
                "manifest_path": str(manifest_path),
                "target": data.get("target"),
                "captured_at": data.get("captured_at"),
            }
        except Exception as e:
            return {
                "incident_id": safe_id,
                "verified": False,
                "error": str(e),
            }
