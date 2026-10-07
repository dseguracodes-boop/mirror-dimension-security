import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional
from uuid import uuid4
import docker
from docker.errors import DockerException

from core.assets import AssetRegistry
from core.bus import EventBus
from core.models import MirrorEvent

logger = logging.getLogger("mirror.adapters.docker")


class DockerEventListener:
    """Streams and normalizes Docker daemon lifecycle and exec events in real-time."""

    def __init__(
        self,
        bus: EventBus,
        assets: AssetRegistry,
        client: Optional[docker.DockerClient] = None,
    ) -> None:
        self.bus = bus
        self.assets = assets
        try:
            self.client = client or docker.from_env()
        except DockerException as e:
            logger.warning("Docker daemon connection failed: %s", e)
            self.client = None

        self._running: bool = False
        self._listener_task: Optional[asyncio.Task] = None

    def is_available(self) -> bool:
        if not self.client:
            return False
        try:
            self.client.ping()
            return True
        except Exception:
            return False

    def normalize_event(self, raw_event: Dict[str, Any]) -> Optional[MirrorEvent]:
        """Convert a raw Docker event dictionary into a structured MirrorEvent."""
        event_type = raw_event.get("Type")
        if event_type != "container":
            return None

        action = raw_event.get("Action", "")
        actor = raw_event.get("Actor", {})
        attributes = actor.get("Attributes", {})
        container_name = attributes.get("name", "")
        container_id = actor.get("ID", "")[:12]
        image_name = attributes.get("image", "")

        # Match against AssetRegistry
        asset = self.assets.find_by_container_name(container_name)
        asset_id = asset.id if asset else None

        # Categorize threat severity and attack stages
        severity = "low"
        attack_stage = "execution"
        normalized_type = "docker_lifecycle"

        if "exec_create" in action or "exec_start" in action:
            normalized_type = "process_anomaly"
            severity = "high" if (asset and asset.criticality.value in ("critical", "high")) else "medium"
            attack_stage = "execution"

        elif action in ("kill", "oom"):
            normalized_type = "container_crash"
            severity = "medium"

        elif action in ("pause", "unpause"):
            normalized_type = "container_state_change"

        return MirrorEvent(
            id=uuid4(),
            timestamp=datetime.now(timezone.utc),
            source="docker",
            sensor="docker_events",
            event_type=normalized_type,
            attack_stage=attack_stage,
            asset_id=asset_id,
            container_id=container_name or container_id,
            severity=severity,
            confidence=0.85 if "exec" in action else 0.70,
            command=attributes.get("execID"),
            evidence={
                "action": action,
                "container_name": container_name,
                "container_id": container_id,
                "image": image_name,
                "time": raw_event.get("time"),
            },
        )

    async def start(self) -> None:
        """Start listening to Docker events asynchronously."""
        if not self.is_available():
            logger.warning("Docker listener cannot start: Docker daemon unavailable.")
            return

        self._running = True
        loop = asyncio.get_running_loop()
        self._listener_task = asyncio.create_task(self._event_loop(loop))
        logger.info("Docker Event Stream Listener ACTIVE")

    async def _event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        def get_event_stream():
            return self.client.events(decode=True)

        try:
            # Run blocking docker-py events generator in a separate thread
            stream = await loop.run_in_executor(None, get_event_stream)
            for raw_event in stream:
                if not self._running:
                    break
                event = self.normalize_event(raw_event)
                if event:
                    await self.bus.publish(event)
        except Exception as e:
            if self._running:
                logger.error("Error in Docker event stream loop: %s", e)

    def stop(self) -> None:
        self._running = False
        if self._listener_task and not self._listener_task.done():
            self._listener_task.cancel()
        logger.info("Docker Event Stream Listener STOPPED")
