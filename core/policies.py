from pathlib import Path
from typing import Dict, List, Optional, Union
import yaml
from core.models import (
    ActionType,
    Asset,
    Criticality,
    MirrorEvent,
    PolicyDecision,
    PolicyRule,
    ThreatLevel,
)


class PolicyEngine:
    """Evaluates declarative security policies against events and assets."""

    def __init__(self) -> None:
        self._rules: List[PolicyRule] = []

    def add_rule(self, rule: PolicyRule) -> None:
        self._rules.append(rule)

    def load_from_yaml(self, path_or_content: Union[str, Path]) -> None:
        """Load policy rules from a YAML file or string."""
        if isinstance(path_or_content, Path) or (isinstance(path_or_content, str) and "\n" not in path_or_content and Path(path_or_content).exists()):
            file_path = Path(path_or_content)
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        else:
            data = yaml.safe_load(str(path_or_content))

        if not data or "policies" not in data:
            return

        for item in data["policies"]:
            # Support both flat and nested 'decision' formats
            if "decision" in item:
                rule_dict = {
                    "name": item.get("name", "unnamed_policy"),
                    "description": item.get("description"),
                    "event_type": item.get("event_type"),
                    "sensor": item.get("sensor"),
                    "attack_stage": item.get("attack_stage"),
                    "asset_criticality": item.get("asset_criticality"),
                    "asset_type": item.get("asset_type"),
                    "confidence_min": float(item.get("confidence_min", 0.0)),
                    "threat": item["decision"].get("threat", ThreatLevel.LOW),
                    "action": item["decision"].get("action", ActionType.MONITOR),
                }
            else:
                rule_dict = item

            self.add_rule(PolicyRule.model_validate(rule_dict))

    def evaluate(self, event: MirrorEvent, asset: Optional[Asset] = None) -> PolicyDecision:
        """Evaluate an event and its target asset to find the best matching policy rule."""
        asset_criticality = asset.criticality if asset else Criticality.LOW
        asset_type = asset.type if asset else None

        for rule in self._rules:
            # 1. Check confidence threshold
            if event.confidence < rule.confidence_min:
                continue

            # 2. Check event_type match
            if rule.event_type and rule.event_type != event.event_type:
                continue

            # 3. Check sensor match
            if rule.sensor and rule.sensor != event.sensor:
                continue

            # 4. Check attack_stage match
            if rule.attack_stage and rule.attack_stage != event.attack_stage:
                continue

            # 5. Check asset_criticality match
            if rule.asset_criticality and rule.asset_criticality != asset_criticality:
                continue

            # 6. Check asset_type match
            if rule.asset_type and rule.asset_type != asset_type:
                continue

            # Match found
            matched_candidate = PolicyDecision(
                threat=rule.threat,
                action=rule.action,
                reason=f"Matched policy rule: {rule.name}",
                confidence=event.confidence,
            )
            return self._apply_invariants(event, asset, matched_candidate)

        # Default fallback decision if no rule matches
        default_threat = (
            ThreatLevel.CRITICAL if event.severity == "critical"
            else ThreatLevel.HIGH if event.severity == "high"
            else ThreatLevel.MEDIUM if event.severity == "medium"
            else ThreatLevel.LOW
        )
        default_action = (
            ActionType.ISOLATE if default_threat == ThreatLevel.CRITICAL
            else ActionType.MONITOR if default_threat in (ThreatLevel.HIGH, ThreatLevel.MEDIUM)
            else ActionType.ALLOW
        )

        candidate = PolicyDecision(
            threat=default_threat,
            action=default_action,
            reason="Default fallback policy (no specific rule matched)",
            confidence=event.confidence,
        )

        return self._apply_invariants(event, asset, candidate)

    def _apply_invariants(
        self,
        event: MirrorEvent,
        asset: Optional[Asset],
        decision: PolicyDecision,
    ) -> PolicyDecision:
        """Enforces structural security invariants that cannot be broken or bypassed by sub-thresholds."""
        asset_criticality = asset.criticality if asset else Criticality.LOW

        # Invariant 1: Untrusted Sensor Telemetry (Anti-False-Flag DoS)
        if not getattr(event, "verified_sensor", True):
            if decision.action in (ActionType.EMERGENCY_FREEZE, ActionType.ISOLATE):
                return PolicyDecision(
                    threat=ThreatLevel.MEDIUM,
                    action=ActionType.MONITOR,
                    reason="Invariant: Unauthenticated sensor telemetry cannot trigger destructive freeze; sandboxed to MONITOR",
                    confidence=0.5,
                )

        # Invariant 2: Zero-Trust Deception Rule (Zero Legitimate Business Traffic)
        is_deception = (
            event.event_type in ("canary_trigger", "fake_port_probe")
            or event.source in ("canary", "opencanary")
            or event.sensor in ("decoy_file", "fake_port")
        )
        if is_deception:
            # Canary traps have no legitimate traffic; they must NEVER degrade to ALLOW or MONITOR on secrets
            is_critical = (asset_criticality == Criticality.CRITICAL) or (event.asset_id == "secrets")
            if is_critical:
                if decision.action != ActionType.EMERGENCY_FREEZE:
                    return PolicyDecision(
                        threat=ThreatLevel.CRITICAL,
                        action=ActionType.EMERGENCY_FREEZE,
                        reason="Invariant: Zero-Trust Deception violation on critical secret canary; enforced EMERGENCY_FREEZE",
                        confidence=max(event.confidence, 0.95),
                    )
            else:
                if decision.action == ActionType.ALLOW:
                    return PolicyDecision(
                        threat=ThreatLevel.HIGH,
                        action=ActionType.ISOLATE,
                        reason="Invariant: Deception honeypot probe cannot degrade to ALLOW; enforced ISOLATE",
                        confidence=max(event.confidence, 0.85),
                    )

        # Invariant 3: Container Breakout Boundary Rule
        if event.event_type == "container_escape" and event.confidence >= 0.70:
            if decision.action not in (ActionType.EMERGENCY_FREEZE, ActionType.ISOLATE):
                return PolicyDecision(
                    threat=ThreatLevel.CRITICAL,
                    action=ActionType.EMERGENCY_FREEZE,
                    reason="Invariant: Container escape breakout violates host boundary isolation",
                    confidence=event.confidence,
                )

        return decision

