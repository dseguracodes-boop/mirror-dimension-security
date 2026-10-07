"""Filesystem anomaly and canary file detection adapter."""

from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Callable, Dict, List, Optional
from uuid import uuid4

from core.bus import EventBus
from core.models import MirrorEvent

logger = logging.getLogger("mirror.adapters.filesystem")


class FilesystemWatcher:
    """Monitors watched files and decoy canary paths for unauthorized access or modification."""

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._watched_files: Dict[Path, float] = {}

    def watch_path(self, path: Path) -> None:
        """Register a path to watch for mtime modifications."""
        p = Path(path).resolve()
        mtime = p.stat().st_mtime if p.exists() else 0.0
        self._watched_files[p] = mtime
        logger.info("Watching filesystem path: %s", p)

    async def scan_modifications(self) -> List[MirrorEvent]:
        """Scan watched files for timestamp changes or deletions and emit events."""
        events: List[MirrorEvent] = []
        for path, last_mtime in list(self._watched_files.items()):
            if not path.exists():
                event = MirrorEvent(
                    id=uuid4(),
                    timestamp=datetime.now(timezone.utc),
                    source="filesystem",
                    sensor="file_watcher",
                    event_type="canary_trigger",
                    attack_stage="credential_access",
                    asset_id="secrets",
                    severity="critical",
                    confidence=0.99,
                    path=str(path),
                    evidence={"action": "deleted", "path": str(path)},
                )
                events.append(event)
                await self.bus.publish(event)
            else:
                current_mtime = path.stat().st_mtime
                if current_mtime > last_mtime:
                    self._watched_files[path] = current_mtime
                    event = MirrorEvent(
                        id=uuid4(),
                        timestamp=datetime.now(timezone.utc),
                        source="filesystem",
                        sensor="file_watcher",
                        event_type="canary_trigger",
                        attack_stage="credential_access",
                        asset_id="secrets",
                        severity="high",
                        confidence=0.95,
                        path=str(path),
                        evidence={"action": "modified", "path": str(path), "mtime": current_mtime},
                    )
                    events.append(event)
                    await self.bus.publish(event)
        return events
