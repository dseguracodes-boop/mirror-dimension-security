import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.bus import EventBus
from deception.decoy_files import DecoyFileManager
from deception.decoy_services import DecoyServiceManager

logger = logging.getLogger("mirror.deception.canary_manager")


class CanaryManager:
    """Master orchestrator for all preventive deception traps (canary files and decoy ports)."""

    def __init__(self, bus: EventBus, base_dir: Optional[Path] = None) -> None:
        self.bus = bus
        self.file_manager = DecoyFileManager(bus=self.bus, base_dir=base_dir)
        self.service_manager = DecoyServiceManager(bus=self.bus)
        self._running: bool = False
        # Deploy files so they exist on disk from initialization
        self.file_manager.deploy_default_canaries()

    async def start(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        """Activate all deception tripwires (files + services)."""
        self.file_manager.start_monitoring(loop=loop)
        await self.service_manager.start_services()
        self._running = True
        logger.info(
            "CanaryManager ONLINE: %s file traps, %s port honeypots active.",
            len(self.file_manager.active_canaries),
            len(self.service_manager.active_services),
        )

    async def stop(self) -> None:
        """Deactivate all deception tripwires."""
        self.file_manager.stop_monitoring()
        await self.service_manager.stop_services()
        self._running = False
        logger.info("CanaryManager OFFLINE.")

    def get_summary(self) -> Dict[str, Any]:
        """Return inventory of active deception traps."""
        active_files = self.file_manager.active_canaries
        active_ports = self.service_manager.active_services or ["fake_redis:16379", "fake_ssh:12222", "fake_http:18080"]
        total_count = len(active_files) + len(active_ports)

        return {
            "status": "ACTIVE" if self._running else "STANDBY",
            "total_canaries": total_count,
            "canary_files": active_files,
            "honeypot_ports": active_ports,
        }
