import asyncio
from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from core.bus import EventBus
from core.models import MirrorEvent
from deception.decoy_secrets import DecoySecretGenerator

logger = logging.getLogger("mirror.deception.files")


class CanaryFileEventHandler(FileSystemEventHandler):
    """Watches specific decoy files and notifies the event bus upon tampering or access."""

    def __init__(self, bus: EventBus, canary_paths: Dict[Path, str], loop: asyncio.AbstractEventLoop) -> None:
        self.bus = bus
        self.canary_paths = {p.resolve(): name for p, name in canary_paths.items()}
        self.loop = loop

    def on_modified(self, event: FileSystemEvent) -> None:
        self._check_and_trigger(event, action="modified")

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._check_and_trigger(event, action="deleted")

    def on_moved(self, event: FileSystemEvent) -> None:
        self._check_and_trigger(event, action="moved")

    def _check_and_trigger(self, event: FileSystemEvent, action: str) -> None:
        event_path = Path(event.src_path).resolve()
        if event_path in self.canary_paths:
            canary_name = self.canary_paths[event_path]
            logger.critical("🚨 CANARY FILE TRIPPED! [%s] %s -> %s", action.upper(), canary_name, event_path)

            mirror_event = MirrorEvent(
                id=uuid4(),
                timestamp=datetime.now(timezone.utc),
                source="deception",
                sensor="decoy_file",
                event_type="canary_trigger",
                attack_stage="credential_access",
                asset_id="secrets",
                severity="critical",
                confidence=0.99,
                path=str(event_path),
                evidence={
                    "canary_name": canary_name,
                    "action": action,
                    "file_path": str(event_path),
                    "is_directory": event.is_directory,
                },
            )

            # Schedule publication on async loop
            if self.loop.is_running():
                asyncio.run_coroutine_threadsafe(self.bus.publish(mirror_event), self.loop)


class DecoyFileManager:
    """Manages placement and active monitoring of canary and decoy tripwire files."""

    def __init__(self, bus: EventBus, base_dir: Optional[Path] = None) -> None:
        self.bus = bus
        self.base_dir = base_dir or Path(__file__).resolve().parent.parent
        self._canary_files: Dict[Path, str] = {}
        self._observer: Optional[Observer] = None
        self._event_handler: Optional[CanaryFileEventHandler] = None

    def deploy_default_canaries(self) -> List[Path]:
        """Deploy realistic honeypot credential files into the project."""
        deployed = []

        # 1. Fake .env.backup
        env_backup = self.base_dir / ".env.backup"
        aws_keys = DecoySecretGenerator.generate_aws_key_pair("prod")
        pg_uri = DecoySecretGenerator.generate_postgres_uri()
        openai_key = DecoySecretGenerator.generate_api_key("openai")

        content = (
            "# Production secrets backup - DO NOT COMMIT\n"
            f"DATABASE_URL={pg_uri}\n"
            f"AWS_ACCESS_KEY_ID={aws_keys['AWS_ACCESS_KEY_ID']}\n"
            f"AWS_SECRET_ACCESS_KEY={aws_keys['AWS_SECRET_ACCESS_KEY']}\n"
            f"OPENAI_API_KEY={openai_key}\n"
            "JWT_SECRET=super_secret_dev_signing_key_9941\n"
        )

        with open(env_backup, "w", encoding="utf-8") as f:
            f.write(content)
        self._canary_files[env_backup] = "decoy_env_backup"
        deployed.append(env_backup)

        logger.info("Deployed canary file: %s", env_backup)
        return deployed

    def start_monitoring(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        """Start watchdog observer monitoring the directory containing canaries."""
        if not self._canary_files:
            self.deploy_default_canaries()

        active_loop = loop or asyncio.get_event_loop()
        self._event_handler = CanaryFileEventHandler(self.bus, self._canary_files, active_loop)
        self._observer = Observer()

        # Watch the parent directories of all canaries
        watched_dirs = {p.parent.resolve() for p in self._canary_files.keys()}
        for directory in watched_dirs:
            if directory.exists():
                self._observer.schedule(self._event_handler, str(directory), recursive=False)

        self._observer.start()
        logger.info("Canary file filesystem monitoring ACTIVE on %s", [str(d) for d in watched_dirs])

    def stop_monitoring(self) -> None:
        if self._observer and self._observer.is_alive():
            self._observer.stop()
            self._observer.join()
            logger.info("Canary file filesystem monitoring STOPPED")

    @property
    def active_canaries(self) -> List[str]:
        return list(self._canary_files.values())
