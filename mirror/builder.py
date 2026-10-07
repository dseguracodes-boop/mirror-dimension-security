import logging
from typing import Any, Dict, List, Optional
import docker
from core.models import Asset
from mirror.sanitization import MirrorSanitizer

logger = logging.getLogger("mirror.mirror.builder")


class MirrorBuilder:
    """Builds clean, sanitized container specifications from known-good images."""

    @staticmethod
    def build_mirror_spec(
        asset: Optional[Asset],
        target_name: str,
        original_env: Optional[List[str]] = None,
        docker_client: Optional[docker.DockerClient] = None,
    ) -> Dict[str, Any]:
        """Construct the configuration for a clean mirror instance."""
        candidate_image = None
        if asset and asset.container and asset.container.image:
            candidate_image = asset.container.image
        elif "postgres" in target_name:
            candidate_image = "postgres:16-alpine"
        elif "redis" in target_name:
            candidate_image = "redis:7-alpine"

        # Verify candidate image exists locally or has a valid fallback
        image_name = candidate_image
        if docker_client:
            image_available = False
            if candidate_image:
                try:
                    docker_client.images.get(candidate_image)
                    image_available = True
                except Exception:
                    image_available = False

            if not image_available:
                if candidate_image and "postgres" in candidate_image:
                    image_name = "postgres:16-alpine"
                elif candidate_image and "redis" in candidate_image:
                    image_name = "redis:7-alpine"
                else:
                    image_name = "alpine:latest"
                logger.warning(
                    "Image '%s' not found locally. Safely falling back to known-good base image '%s'",
                    candidate_image,
                    image_name,
                )
        elif not image_name:
            image_name = "alpine:latest"

        # 2. Sanitize environment variables and inject decoy secrets
        raw_env = original_env or []
        sanitized_env = MirrorSanitizer.sanitize_environment(raw_env)

        mirror_container_name = f"mirror-{target_name}"

        spec: Dict[str, Any] = {
            "name": mirror_container_name,
            "image": image_name,
            "environment": sanitized_env,
            "labels": {
                "managed_by": "dimension_espejo",
                "role": "mirror_instance",
                "target_asset": asset.id if asset else target_name,
                "sanitized": "true",
            },
            "command": None,
        }

        # Handle specific base service presets
        is_postgres = (
            "postgres" in target_name
            or (asset and ("postgres" in asset.id or asset.type.value == "database"))
            or (image_name and "postgres" in image_name)
        )
        is_redis = (
            "redis" in target_name
            or (asset and "redis" in asset.id)
            or (image_name and "redis" in image_name)
        )

        if is_postgres:
            spec["environment"].append("POSTGRES_PASSWORD=mirror_decoy_pass_9941")
            spec["environment"].append("POSTGRES_DB=mirror_db")
        elif is_redis:
            spec["command"] = "redis-server --requirepass mirror_decoy_redis_pass_9941"
        elif "alpine" in image_name:
            spec["command"] = "sleep 3600"

        logger.info(
            "Constructed Mirror Spec for '%s': Image=%s (Clean Base), EnvCount=%s",
            target_name,
            image_name,
            len(sanitized_env),
        )
        return spec
