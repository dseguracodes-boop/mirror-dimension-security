from uuid import uuid4
from core.models import (
    ActionType,
    Asset,
    AssetProtections,
    AssetType,
    Criticality,
    Incident,
    MirrorEvent,
    ThreatLevel,
)


def test_mirror_event_creation():
    event = MirrorEvent(
        source="canary",
        sensor="decoy_file",
        event_type="canary_trigger",
        attack_stage="credential_access",
        asset_id="secrets",
        severity="critical",
        confidence=0.99,
        path=".env.backup",
    )
    assert event.event_type == "canary_trigger"
    assert event.confidence == 0.99
    assert event.severity == "critical"
    assert event.attack_stage == "credential_access"


def test_asset_model():
    asset = Asset(
        id="api",
        type=AssetType.CONTAINER,
        criticality=Criticality.HIGH,
        protections=AssetProtections(filesystem=True, canary=True),
    )
    assert asset.id == "api"
    assert asset.type == AssetType.CONTAINER
    assert asset.criticality == Criticality.HIGH
    assert asset.protections.filesystem is True
    assert asset.protections.network is False


def test_incident_model():
    inc = Incident(
        id="INC-2026-0001",
        asset_ids=["api"],
        threat_level=ThreatLevel.CRITICAL,
        actions=[ActionType.EMERGENCY_FREEZE],
    )
    assert inc.id == "INC-2026-0001"
    assert inc.threat_level == ThreatLevel.CRITICAL
    assert ActionType.EMERGENCY_FREEZE in inc.actions
