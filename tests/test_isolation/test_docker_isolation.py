from unittest.mock import MagicMock
from isolation.docker import DockerIsolationManager


def test_docker_isolation_freeze_mocked():
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_container.name = "test-api"
    mock_container.short_id = "abc123"
    mock_container.status = "running"
    mock_client.containers.get.return_value = mock_container

    iso = DockerIsolationManager(client=mock_client)
    success = iso.freeze_container("test-api")

    assert success is True
    mock_container.pause.assert_called_once()


def test_docker_isolation_unfreeze_mocked():
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_container.name = "test-api"
    mock_container.status = "paused"
    mock_client.containers.get.return_value = mock_container

    iso = DockerIsolationManager(client=mock_client)
    success = iso.unfreeze_container("test-api")

    assert success is True
    mock_container.unpause.assert_called_once()
