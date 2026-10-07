"""osquery process and socket telemetry adapter."""

from datetime import datetime, timezone
import json
import logging
import shutil
import subprocess
from typing import Any, Dict, List, Optional
from uuid import uuid4

from core.bus import EventBus
from core.models import MirrorEvent

logger = logging.getLogger("mirror.adapters.osquery")


class OsqueryAdapter:
    """Adapter for osquery process, socket, and shell execution auditing."""

    def __init__(self, bus: EventBus, osqueryi_bin: str = "osqueryi") -> None:
        self.bus = bus
        self.osqueryi_bin = osqueryi_bin

    def is_available(self) -> bool:
        return shutil.which(self.osqueryi_bin) is not None

    def query(self, sql: str) -> List[Dict[str, Any]]:
        """Execute an ad-hoc osquery query via osqueryi CLI returning JSON results."""
        if not self.is_available():
            logger.debug("osqueryi binary not found on host PATH")
            return []
        try:
            res = subprocess.run(
                [self.osqueryi_bin, "--json", sql],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 and res.stdout.strip():
                return json.loads(res.stdout)
            return []
        except Exception as e:
            logger.warning("osquery execution failed: %s", e)
            return []

    async def check_suspicious_processes(self, asset_id: str = "host") -> List[MirrorEvent]:
        """Scan running processes for known attacker utilities (e.g. nmap, nc, reverse shells)."""
        sql = "SELECT pid, name, path, cmdline, uid FROM processes WHERE cmdline LIKE '%nc -e%' OR cmdline LIKE '%bash -i%' OR name IN ('nmap', 'masscan', 'hydra');"
        rows = self.query(sql)
        events: List[MirrorEvent] = []

        for row in rows:
            event = MirrorEvent(
                id=uuid4(),
                timestamp=datetime.now(timezone.utc),
                source="osquery",
                sensor="process_monitor",
                event_type="process_anomaly",
                attack_stage="execution",
                asset_id=asset_id,
                severity="critical",
                confidence=0.92,
                command=row.get("cmdline", ""),
                process=row.get("name", ""),
                evidence=row,
            )
            events.append(event)
            await self.bus.publish(event)

        return events
