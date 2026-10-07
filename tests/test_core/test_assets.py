from pathlib import Path
from core.assets import AssetRegistry
from core.models import Asset, AssetType, Criticality


def test_asset_registry_in_memory():
    registry = AssetRegistry()
    asset = Asset(id="redis", type=AssetType.SERVICE, criticality=Criticality.MEDIUM)
    registry.register(asset)

    assert registry.get("redis") is not None
    assert registry.get("redis").criticality == Criticality.MEDIUM
    assert registry.get("nonexistent") is None


def test_asset_registry_load_yaml():
    yaml_content = """
    assets:
      api:
        type: container
        criticality: high
        container:
          name: api-service
          ports: [8000]
        protections:
          filesystem: true
          canary: true
    """
    registry = AssetRegistry()
    registry.load_from_yaml(yaml_content)

    api = registry.get("api")
    assert api is not None
    assert api.type == AssetType.CONTAINER
    assert api.criticality == Criticality.HIGH
    assert api.protections.canary is True
    assert registry.find_by_port(8000) == api
    assert registry.find_by_container_name("api-service") == api
