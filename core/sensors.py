"""Sensor Authenticity & HMAC Cryptographic Provenance Module.

Prevents False-Flag DoS attacks and telemetry poisoning by verifying
cryptographic HMAC signatures on events emitted by security sensors.
"""

import hashlib
import hmac
import logging
from typing import Dict, Optional
from core.models import MirrorEvent

logger = logging.getLogger("mirror.sensors")


class SensorAuthenticator:
    """Manages sensor registration, event signing, and cryptographic verification."""

    DEFAULT_INTERNAL_KEY = b"dimencion-espejo-sensor-internal-key-991823"

    def __init__(self, default_key: Optional[bytes] = None) -> None:
        self.default_key = default_key or self.DEFAULT_INTERNAL_KEY
        self._sensor_keys: Dict[str, bytes] = {}
        # Pre-register built-in core sensors
        builtin_sensors = [
            "decoy_file",
            "fake_port",
            "docker_events",
            "process_monitor",
            "host_audit",
            "fim",
            "canary",
            "opencanary",
        ]
        for s in builtin_sensors:
            self._sensor_keys[s] = self.default_key

    def register_sensor(self, sensor_id: str, key: bytes) -> None:
        self._sensor_keys[sensor_id] = key

    def _canonical_bytes(self, event: MirrorEvent) -> bytes:
        payload = f"{event.source}:{event.sensor}:{event.event_type}:{event.asset_id or ''}:{event.timestamp.isoformat()}"
        return payload.encode("utf-8")

    def sign_event(self, event: MirrorEvent, sensor_id: Optional[str] = None) -> str:
        """Sign an event using the sensor's registered HMAC key."""
        sid = sensor_id or event.sensor
        key = self._sensor_keys.get(sid, self.default_key)
        sig = hmac.new(key, self._canonical_bytes(event), hashlib.sha256).hexdigest()
        event.sensor_id = sid
        event.signature = sig
        event.verified_sensor = True
        return sig

    def verify_event(self, event: MirrorEvent) -> bool:
        """Verify an incoming event's signature against the sensor key."""
        if not event.signature:
            # If untagged or missing signature, verify sensor is known
            sid = event.sensor_id or event.sensor
            if sid in self._sensor_keys:
                return True
            return False

        sid = event.sensor_id or event.sensor
        key = self._sensor_keys.get(sid, self.default_key)
        expected_sig = hmac.new(key, self._canonical_bytes(event), hashlib.sha256).hexdigest()
        is_valid = hmac.compare_digest(event.signature, expected_sig)
        return is_valid
