import logging
from typing import Dict, List, Optional
import docker
from docker.errors import DockerException, NotFound

logger = logging.getLogger("mirror.isolation.network")

ISOLATED_NETWORK_NAME = "mirror_isolated_net"


class NetworkIsolationManager:
    """Manages Docker network isolation and containment into an internal blackhole bridge."""

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

    def ensure_isolated_network(self) -> Optional[docker.models.networks.Network]:
        """Ensure the internal, non-routable mirror isolation network exists."""
        if not self.is_available():
            return None

        try:
            return self.client.networks.get(ISOLATED_NETWORK_NAME)
        except NotFound:
            try:
                # Create internal network: no gateway out, no internet, isolated
                network = self.client.networks.create(
                    name=ISOLATED_NETWORK_NAME,
                    driver="bridge",
                    internal=True,
                    labels={"managed_by": "dimension_espejo", "role": "quarantine"},
                )
                logger.info("Created internal isolated network: %s", ISOLATED_NETWORK_NAME)
                return network
            except Exception as e:
                logger.error("Failed to create isolated network: %s", e)
                return None

    def isolate_container(self, container_identifier: str) -> Dict[str, Any]:
        """Sever all external network interfaces and move container into internal blackhole."""
        result = {
            "container": container_identifier,
            "disconnected_networks": [],
            "attached_isolated": False,
            "success": False,
        }

        if not self.is_available():
            logger.error("Docker daemon unavailable for network isolation")
            return result

        try:
            container = self.client.containers.get(container_identifier)
            net_settings = container.attrs.get("NetworkSettings", {}).get("Networks", {})

            # 1. Ensure isolated network exists
            isolated_net = self.ensure_isolated_network()

            # 2. Disconnect from all current networks
            for net_name in list(net_settings.keys()):
                if net_name == ISOLATED_NETWORK_NAME:
                    continue
                try:
                    current_net = self.client.networks.get(net_name)
                    current_net.disconnect(container, force=True)
                    result["disconnected_networks"].append(net_name)
                    logger.critical("SEVERED NETWORK LINK: %s disconnected from %s", container.name, net_name)
                except Exception as ex:
                    logger.warning("Error disconnecting from %s: %s", net_name, ex)

            # 3. Connect to internal blackhole network
            if isolated_net:
                try:
                    isolated_net.connect(container)
                    result["attached_isolated"] = True
                    logger.info("ATTACHED TO QUARANTINE NETWORK: %s -> %s", container.name, ISOLATED_NETWORK_NAME)
                except Exception as ex:
                    logger.warning("Error attaching to %s: %s", ISOLATED_NETWORK_NAME, ex)

            result["success"] = bool(result["disconnected_networks"] or result["attached_isolated"])
            return result

        except NotFound:
            logger.error("Container %s not found for network isolation", container_identifier)
            return result
        except Exception as e:
            logger.error("Network isolation failed for %s: %s", container_identifier, e)
            return result
