from unittest.mock import MagicMock
from isolation.network import ISOLATED_NETWORK_NAME, NetworkIsolationManager


def test_network_isolation_disconnect_and_attach():
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_container.name = "test-api"
    mock_container.attrs = {
        "NetworkSettings": {
            "Networks": {
                "bridge": {},
                "project_default": {},
            }
        }
    }
    mock_client.containers.get.return_value = mock_container

    # Mock networks
    mock_bridge = MagicMock()
    mock_project_net = MagicMock()
    mock_isolated_net = MagicMock()

    def get_network(name):
        if name == "bridge":
            return mock_bridge
        if name == "project_default":
            return mock_project_net
        if name == ISOLATED_NETWORK_NAME:
            return mock_isolated_net
        raise ValueError(f"Unknown {name}")

    mock_client.networks.get.side_effect = get_network

    net_mgr = NetworkIsolationManager(client=mock_client)
    res = net_mgr.isolate_container("test-api")

    assert res["success"] is True
    assert "bridge" in res["disconnected_networks"]
    assert "project_default" in res["disconnected_networks"]
    assert res["attached_isolated"] is True

    # Check network disconnect called
    mock_bridge.disconnect.assert_called_once_with(mock_container, force=True)
    mock_project_net.disconnect.assert_called_once_with(mock_container, force=True)
    mock_isolated_net.connect.assert_called_once_with(mock_container)
