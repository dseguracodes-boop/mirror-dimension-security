from unittest.mock import MagicMock
from core.models import Asset, AssetContainerConfig, AssetType, Criticality
from mirror.runtime import MirrorRuntime


def test_mirror_runtime_instantiation_mocked():
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_container.id = "mirror_id_999"
    mock_container.short_id = "mir999"
    mock_client.containers.run.return_value = mock_container

    runtime = MirrorRuntime(client=mock_client)
    asset = Asset(
        id="api",
        type=AssetType.CONTAINER,
        criticality=Criticality.HIGH,
        container=AssetContainerConfig(name="developer-api", image="alpine"),
    )

    mirror_id = runtime.instantiate_mirror(asset, "developer-api")
    assert mirror_id == "mir999"
    assert len(runtime.list_active_mirrors()) == 1
    assert runtime.list_active_mirrors()[0]["name"] == "mirror-developer-api"


def test_mirror_runtime_destruction_mocked():
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_client.containers.get.return_value = mock_container

    runtime = MirrorRuntime(client=mock_client)
    runtime._active_mirrors["mirror-developer-api"] = {"name": "mirror-developer-api"}

    success = runtime.destroy_mirror("mirror-developer-api")
    assert success is True
    mock_container.remove.assert_called_once_with(force=True)
    assert "mirror-developer-api" not in runtime._active_mirrors
