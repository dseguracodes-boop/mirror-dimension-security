import logging
from typing import Any, Dict, Optional
import docker
from docker.errors import DockerException, NotFound

logger = logging.getLogger("mirror.isolation.docker")


class DockerIsolationManager:
    """Manages container lifecycle isolation primitives (pause, freeze, inspect)."""

    def __init__(self, client: Optional[docker.DockerClient] = None) -> None:
        try:
            self.client = client or docker.from_env()
        except DockerException as e:
            logger.warning("Could not connect to Docker daemon: %s", e)
            self.client = None

    def is_available(self) -> bool:
        """Check if Docker daemon is accessible."""
        if not self.client:
            return False
        try:
            self.client.ping()
            return True
        except Exception:
            return False

    def freeze_container(self, container_identifier: str) -> bool:
        """Atomically freeze (pause) a running container to halt execution and preserve memory state."""
        if not self.is_available():
            logger.error("Docker daemon unavailable for freezing %s", container_identifier)
            return False

        try:
            container = self.client.containers.get(container_identifier)
            if container.status == "running":
                container.pause()
                logger.critical("CONTAINER FROZEN [PAUSED]: %s (%s)", container.name, container.short_id)
                return True
            else:
                logger.warning("Container %s is in state '%s', cannot freeze", container_identifier, container.status)
                return False
        except NotFound:
            logger.error("Container %s not found for freezing", container_identifier)
            return False
        except Exception as e:
            logger.error("Failed to freeze container %s: %s", container_identifier, e)
            return False

    def unfreeze_container(self, container_identifier: str) -> bool:
        """Unpause a frozen container."""
        if not self.is_available():
            return False
        try:
            container = self.client.containers.get(container_identifier)
            if container.status == "paused":
                container.unpause()
                logger.info("CONTAINER UNPAUSED: %s", container.name)
                return True
            return False
        except Exception as e:
            logger.error("Failed to unfreeze container %s: %s", container_identifier, e)
            return False

    def inspect_container(self, container_identifier: str) -> Optional[Dict[str, Any]]:
        """Retrieve detailed container inspection data."""
        if not self.is_available():
            return None
        try:
            container = self.client.containers.get(container_identifier)
            return container.attrs
        except Exception as e:
            logger.error("Failed to inspect container %s: %s", container_identifier, e)
            return None
