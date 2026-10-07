import logging
from typing import Any, Dict, List, Optional
import docker
from docker.errors import DockerException, NotFound

from core.models import Asset
from mirror.builder import MirrorBuilder
from mirror.network import MIRROR_WORLD_NETWORK_NAME, MirrorNetworkManager

logger = logging.getLogger("mirror.mirror.runtime")


class MirrorRuntime:
    """Coordinates lifecycle, execution, and teardown of active Mirror World instances."""

    def __init__(self, client: Optional[docker.DockerClient] = None) -> None:
        try:
            self.client = client or docker.from_env()
        except DockerException as e:
            logger.warning("Could not connect to Docker daemon for MirrorRuntime: %s", e)
            self.client = None

        self.network_manager = MirrorNetworkManager(client=self.client)
        self._active_mirrors: Dict[str, Dict[str, Any]] = {}

    def is_available(self) -> bool:
        if not self.client:
            return False
        try:
            self.client.ping()
            return True
        except Exception:
            return False

    def instantiate_mirror(
        self,
        asset: Optional[Asset],
        target_name: str,
        original_env: Optional[List[str]] = None,
    ) -> Optional[str]:
        """Spawn a clean mirror instance in the isolated mirror_world_net network."""
        if not self.is_available():
            logger.error("Docker daemon unavailable to launch Mirror instance for %s", target_name)
            return None

        # 1. Build clean specification with verified base image
        spec = MirrorBuilder.build_mirror_spec(asset, target_name, original_env, docker_client=self.client)
        mirror_name = spec["name"]

        # 2. Ensure isolated network exists
        self.network_manager.ensure_mirror_network()

        # 3. Clean up any previous dead mirror container with same name
        try:
            old = self.client.containers.get(mirror_name)
            old.remove(force=True)
            logger.info("Removed stale mirror container: %s", mirror_name)
        except NotFound:
            pass
        except Exception as e:
            logger.warning("Error checking stale mirror %s: %s", mirror_name, e)

        # 4. Run the clean mirror container
        try:
            container = self.client.containers.run(
                image=spec["image"],
                name=mirror_name,
                environment=spec["environment"],
                labels=spec["labels"],
                command=spec["command"],
                network=MIRROR_WORLD_NETWORK_NAME,
                detach=True,
            )
            mirror_info = {
                "id": container.id,
                "short_id": container.short_id,
                "name": mirror_name,
                "target_asset": asset.id if asset else target_name,
                "image": spec["image"],
                "network": MIRROR_WORLD_NETWORK_NAME,
                "status": "RUNNING",
            }
            self._active_mirrors[mirror_name] = mirror_info
            logger.critical(
                "🪞 MIRROR WORLD INSTANCE ONLINE: %s (%s) on image '%s' in network '%s'",
                mirror_name,
                container.short_id,
                spec["image"],
                MIRROR_WORLD_NETWORK_NAME,
            )
            return container.short_id

        except Exception as e:
            logger.error("Failed to run mirror container %s: %s", mirror_name, e)
            return None

    def destroy_mirror(self, mirror_name: str) -> bool:
        """Tear down and remove a mirror instance."""
        if not self.is_available():
            return False

        try:
            container = self.client.containers.get(mirror_name)
            container.remove(force=True)
            if mirror_name in self._active_mirrors:
                del self._active_mirrors[mirror_name]
            logger.info("Mirror instance destroyed: %s", mirror_name)
            return True
        except NotFound:
            return False
        except Exception as e:
            logger.error("Error destroying mirror %s: %s", mirror_name, e)
            return False

    def list_active_mirrors(self) -> List[Dict[str, Any]]:
        """List active mirror containers."""
        return list(self._active_mirrors.values())
