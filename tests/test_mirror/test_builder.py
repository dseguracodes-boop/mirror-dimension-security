from core.models import Asset, AssetContainerConfig, AssetType, Criticality
from mirror.builder import MirrorBuilder


def test_build_mirror_spec_known_good_image():
    asset = Asset(
        id="postgres",
        type=AssetType.DATABASE,
        criticality=Criticality.CRITICAL,
        container=AssetContainerConfig(name="dev-pg", image="postgres:16-alpine"),
    )

    spec = MirrorBuilder.build_mirror_spec(asset, "dev-pg", ["POSTGRES_USER=admin"])

    assert spec["name"] == "mirror-dev-pg"
    assert spec["image"] == "postgres:16-alpine"  # Known-good clean base image!
    assert spec["labels"]["role"] == "mirror_instance"
    assert spec["labels"]["sanitized"] == "true"
    assert any("POSTGRES_DB=mirror_db" in env for env in spec["environment"])


def test_build_mirror_spec_generic_service():
    asset = Asset(
        id="api",
        type=AssetType.CONTAINER,
        criticality=Criticality.HIGH,
        container=AssetContainerConfig(name="dev-api", image="my-api:latest"),
    )

    spec = MirrorBuilder.build_mirror_spec(asset, "dev-api")
    assert spec["name"] == "mirror-dev-api"
    assert spec["image"] == "my-api:latest"
    assert any("MIRROR_WORLD_ACTIVE=true" in env for env in spec["environment"])
