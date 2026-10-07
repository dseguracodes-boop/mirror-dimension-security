import logging
from typing import Optional
import docker
from docker.errors import DockerException, NotFound

logger = logging.getLogger("mirror.mirror.network")

MIRROR_WORLD_NETWORK_NAME = "mirror_world_net"


class MirrorNetworkManager:
    """Manages the isolated network dedicated to Mirror World decoy instances."""

    def __init__(self, client: Optional[docker.DockerClient] = None) -> None:
        try:
            self.client = client or docker.from_env()
        except DockerException as e:
            logger.warning("Could not connect to Docker daemon: %s", e)
            self.client = None

    def is_available(self) -> bool:
        if not self.client:
            return False
        try:
            self.client.ping()
            return True
        except Exception:
            return False

    def ensure_mirror_network(self) -> Optional[docker.models.networks.Network]:
        """Ensure the sandboxed mirror network exists with no access to production networks."""
        if not self.is_available():
            return None

        try:
            return self.client.networks.get(MIRROR_WORLD_NETWORK_NAME)
        except NotFound:
            try:
                network = self.client.networks.create(
                    name=MIRROR_WORLD_NETWORK_NAME,
                    driver="bridge",
                    internal=False,  # Allows inter-container traffic inside the mirror world
                    labels={"managed_by": "dimension_espejo", "role": "mirror_world"},
                )
                logger.info("Created Mirror World network: %s", MIRROR_WORLD_NETWORK_NAME)
                return network
            except Exception as e:
                logger.error("Failed to create mirror network: %s", e)
                return None
