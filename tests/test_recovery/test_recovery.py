from core.incidents import IncidentManager
from core.models import ActionType, IncidentStatus, MirrorEvent, PolicyDecision, ThreatLevel
from mirror.traffic_switch import TrafficSwitch
from recovery.manager import RecoveryManager


def test_recovery_baseline_registration_and_verification():
    mgr = RecoveryManager()
    record = mgr.register_baseline(
        asset_id="postgres",
        known_good_image="postgres:16-alpine",
        config_payload={"port": 5432},
    )

    assert record.asset_id == "postgres"
    assert record.sha256_seal is not None
    assert len(record.sha256_seal) == 64

    # Verify matching image
    assert mgr.verify_image_integrity("postgres", "postgres:16-alpine") is True
    # Verify tampered image
    assert mgr.verify_image_integrity("postgres", "evil-backdoored-postgres:latest") is False


def test_recovery_rollback_lifecycle():
    mgr = RecoveryManager()
    switch = TrafficSwitch()
    incidents = IncidentManager()

    switch.register_route("api", "developer-api:8000", "mirror-developer-api:8000")
    switch.divert_to_mirror("api")
    assert switch.get_route("api").is_diverted is True

    # Spawn mock open incident
    ev = MirrorEvent(
        source="docker",
        sensor="docker_events",
        event_type="container_escape",
        asset_id="api",
    )
    dec = PolicyDecision(threat=ThreatLevel.CRITICAL, action=ActionType.EMERGENCY_FREEZE, reason="Test")
    inc = incidents.process_event(ev, dec)
    assert inc.status == IncidentStatus.OPEN

    # Execute automated rollback
    report = mgr.execute_rollback(
        asset_id="api",
        incident_id=inc.id,
        traffic_switch=switch,
        incident_manager=incidents,
    )

    assert report["traffic_restored"] is True
    assert report["incident_resolved"] is True
    assert switch.get_route("api").is_diverted is False
    assert inc.status == IncidentStatus.RESOLVED
