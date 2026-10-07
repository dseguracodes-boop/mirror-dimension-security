import pytest
from core.models import ActionType, Criticality, MirrorEvent, ThreatLevel
from core.policies import PolicyEngine
from core.threat_engine import CumulativeThreatScorer
from core.sensors import SensorAuthenticator


def test_zero_trust_deception_invariant_prevents_canary_bypass():
    engine = PolicyEngine()
    # Event with low spoofed confidence and severity
    ev = MirrorEvent(
        source="canary",
        sensor="decoy_file",
        event_type="canary_trigger",
        attack_stage="credential_access",
        asset_id="secrets",
        severity="low",
        confidence=0.10,  # Extremely low confidence
    )

    decision = engine.evaluate(ev)
    # The invariant must guarantee EMERGENCY_FREEZE on secret canaries
    assert decision.threat == ThreatLevel.CRITICAL
    assert decision.action == ActionType.EMERGENCY_FREEZE
    assert "Zero-Trust Deception" in decision.reason


def test_untrusted_sensor_invariant_sandboxes_to_monitor():
    engine = PolicyEngine()
    # Untrusted / unverified external event
    ev = MirrorEvent(
        source="untrusted_network",
        sensor="spoofed_sensor",
        event_type="container_escape",
        asset_id="api",
        severity="critical",
        confidence=0.99,
        verified_sensor=False,
    )

    decision = engine.evaluate(ev)
    # Untrusted sensor must not cause EMERGENCY_FREEZE
    assert decision.action == ActionType.MONITOR
    assert "Unauthenticated sensor" in decision.reason


def test_cumulative_threat_scorer_escalates_on_repeated_probes():
    scorer = CumulativeThreatScorer(window_seconds=10.0)
    
    # 3 moderate events in quick succession
    for i in range(3):
        ev = MirrorEvent(
            source="osquery",
            sensor="process_monitor",
            event_type="process_anomaly",
            asset_id="postgres",
            severity="high",
            confidence=0.90,
        )
        dec = scorer.record_and_evaluate(
            ev,
            candidate_decision=PolicyEngine().evaluate(ev),
        )

    # Cumulative score should have crossed the critical threshold
    assert dec.threat == ThreatLevel.CRITICAL
    assert dec.action == ActionType.EMERGENCY_FREEZE
    assert "Cumulative Threat Escalation" in dec.reason


def test_sensor_authenticator_hmac_signing_and_verification():
    auth = SensorAuthenticator()
    ev = MirrorEvent(
        source="canary",
        sensor="decoy_file",
        event_type="canary_trigger",
        asset_id="secrets",
    )
    sig = auth.sign_event(ev)
    assert sig is not None
    assert auth.verify_event(ev) is True

    # Tamper with the event
    ev.asset_id = "postgres"
    assert auth.verify_event(ev) is False
