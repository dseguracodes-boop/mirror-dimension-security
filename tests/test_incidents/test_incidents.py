from core.incidents import IncidentManager
from core.models import (
    ActionType,
    IncidentStatus,
    MirrorEvent,
    PolicyDecision,
    ThreatLevel,
)


def test_incident_correlation_and_escalation():
    mgr = IncidentManager()

    e1 = MirrorEvent(
        source="docker",
        sensor="docker_events",
        event_type="suspicious_network",
        asset_id="api",
    )
    d1 = PolicyDecision(threat=ThreatLevel.MEDIUM, action=ActionType.MONITOR, reason="test")

    inc1 = mgr.process_event(e1, d1)
    assert inc1.id.startswith("INC-")
    assert inc1.threat_level == ThreatLevel.MEDIUM
    assert inc1.actions == [ActionType.MONITOR]
    assert inc1.status == IncidentStatus.OPEN

    # Second event on same asset escalates to CRITICAL
    e2 = MirrorEvent(
        source="canary",
        sensor="decoy_file",
        event_type="canary_trigger",
        asset_id="api",
    )
    d2 = PolicyDecision(threat=ThreatLevel.CRITICAL, action=ActionType.EMERGENCY_FREEZE, reason="canary")

    inc2 = mgr.process_event(e2, d2)
    assert inc2.id == inc1.id  # Same incident correlated!
    assert len(inc2.event_ids) == 2
    assert inc2.threat_level == ThreatLevel.CRITICAL
    assert ActionType.EMERGENCY_FREEZE in inc2.actions
