from core.assets import AssetRegistry
from core.decision import ThreatDecisionEngine
from core.models import (
    ActionType,
    Asset,
    AssetType,
    Criticality,
    MirrorEvent,
    ThreatLevel,
)
from core.policies import PolicyEngine


def test_policy_engine_rule_matching():
    yaml_policies = """
    policies:
      - name: canary_alert
        event_type: canary_trigger
        attack_stage: credential_access
        confidence_min: 0.90
        decision:
          threat: critical
          action: emergency_freeze

      - name: process_on_critical
        event_type: process_anomaly
        asset_criticality: critical
        confidence_min: 0.70
        decision:
          threat: high
          action: isolate
    """
    engine = PolicyEngine()
    engine.load_from_yaml(yaml_policies)

    # 1. Canary Event
    event_canary = MirrorEvent(
        source="canary",
        sensor="decoy_file",
        event_type="canary_trigger",
        attack_stage="credential_access",
        confidence=0.95,
    )
    decision = engine.evaluate(event_canary)
    assert decision.threat == ThreatLevel.CRITICAL
    assert decision.action == ActionType.EMERGENCY_FREEZE

    # 2. Process anomaly on Critical asset
    event_proc = MirrorEvent(
        source="osquery",
        sensor="proc_mon",
        event_type="process_anomaly",
        confidence=0.85,
    )
    crit_asset = Asset(id="db", type=AssetType.DATABASE, criticality=Criticality.CRITICAL)
    decision2 = engine.evaluate(event_proc, crit_asset)
    assert decision2.threat == ThreatLevel.HIGH
    assert decision2.action == ActionType.ISOLATE


def test_threat_decision_engine_integration():
    registry = AssetRegistry()
    registry.register(Asset(id="api", type=AssetType.CONTAINER, criticality=Criticality.HIGH))

    policies = PolicyEngine()
    engine = ThreatDecisionEngine(registry, policies)

    event = MirrorEvent(
        source="canary",
        sensor="decoy",
        event_type="canary_trigger",
        asset_id="api",
        severity="critical",
    )
    decision = engine.decide(event)
    assert decision.threat == ThreatLevel.CRITICAL
    assert decision.action == ActionType.ISOLATE
