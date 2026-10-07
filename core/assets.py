from pathlib import Path
from typing import Dict, List, Optional, Union
import yaml
from core.models import Asset, AssetProtections, AssetType, Criticality


class AssetRegistry:
    """Registry and query engine for all assets protected by Dimensión Espejo."""

    def __init__(self) -> None:
        self._assets: Dict[str, Asset] = {}

    def register(self, asset: Asset) -> None:
        """Register an asset in the registry."""
        self._assets[asset.id] = asset

    def get(self, asset_id: str) -> Optional[Asset]:
        """Retrieve an asset by its unique identifier."""
        return self._assets.get(asset_id)

    def list_all(self) -> List[Asset]:
        """List all registered assets."""
        return list(self._assets.values())

    def find_by_container_name(self, name: str) -> Optional[Asset]:
        """Find an asset matching a container name."""
        for asset in self._assets.values():
            if asset.container and asset.container.name == name:
                return asset
        return None

    def find_by_port(self, port: int) -> Optional[Asset]:
        """Find an asset binding a specific port."""
        for asset in self._assets.values():
            if asset.container and port in asset.container.ports:
                return asset
        return None

    def load_from_yaml(self, path_or_content: Union[str, Path]) -> None:
        """Load asset definitions from a YAML file or string."""
        if isinstance(path_or_content, Path) or (isinstance(path_or_content, str) and "\n" not in path_or_content and Path(path_or_content).exists()):
            file_path = Path(path_or_content)
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        else:
            data = yaml.safe_load(str(path_or_content))

        if not data or "assets" not in data:
            return

        raw_assets = data["assets"]
        if isinstance(raw_assets, dict):
            for asset_id, item in raw_assets.items():
                item_copy = dict(item)
                item_copy["id"] = asset_id
                self.register(Asset.model_validate(item_copy))
        elif isinstance(raw_assets, list):
            for item in raw_assets:
                self.register(Asset.model_validate(item))

    def get_criticality(self, asset_id: Optional[str]) -> Criticality:
        """Helper to get asset criticality with fallback to LOW if unknown."""
        if not asset_id:
            return Criticality.LOW
        asset = self.get(asset_id)
        return asset.criticality if asset else Criticality.LOW

    def has_protection(self, asset_id: Optional[str], protection: str) -> bool:
        """Check if an asset has a specific protection enabled."""
        if not asset_id:
            return False
        asset = self.get(asset_id)
        if not asset:
            return False
        return getattr(asset.protections, protection, False)
