import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional
from core.models import MirrorEvent
from core.sensors import SensorAuthenticator

logger = logging.getLogger("mirror.bus")

EventHandler = Callable[[MirrorEvent], Awaitable[None]]


class EventBus:
    """Asynchronous central event bus for Dimensión Espejo."""

    def __init__(self, authenticator: Optional[SensorAuthenticator] = None) -> None:
        self.authenticator = authenticator or SensorAuthenticator()
        self._handlers: Dict[str, List[EventHandler]] = {}
        self._global_handlers: List[EventHandler] = []
        self._history: List[MirrorEvent] = []
        self._max_history: int = 1000

    def subscribe(self, event_type: Optional[str] = None) -> Callable[[EventHandler], EventHandler]:
        """Decorator or direct method to register a subscriber for an event type or globally."""

        def decorator(handler: EventHandler) -> EventHandler:
            if event_type is None or event_type == "*":
                self._global_handlers.append(handler)
            else:
                if event_type not in self._handlers:
                    self._handlers[event_type] = []
                self._handlers[event_type].append(handler)
            return handler

        return decorator

    def register_handler(self, handler: EventHandler, event_type: Optional[str] = None) -> None:
        """Register a handler callback."""
        if event_type is None or event_type == "*":
            self._global_handlers.append(handler)
        else:
            if event_type not in self._handlers:
                self._handlers[event_type] = []
            self._handlers[event_type].append(handler)

    async def publish(self, event: MirrorEvent) -> None:
        """Publish an event to all matched subscribers and store in history."""
        # Authenticate sensor provenance
        if self.authenticator:
            is_valid = self.authenticator.verify_event(event)
            event.verified_sensor = is_valid
            if not is_valid:
                logger.warning(
                    "Sensor verification failed for event %s from sensor '%s' [source: %s]",
                    event.id,
                    event.sensor,
                    event.source,
                )

        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history.pop(0)

        tasks: List[asyncio.Task[Any]] = []

        # Invoke global handlers
        for handler in self._global_handlers:
            tasks.append(asyncio.create_task(self._safe_invoke(handler, event)))

        # Invoke specific handlers
        if event.event_type in self._handlers:
            for handler in self._handlers[event.event_type]:
                tasks.append(asyncio.create_task(self._safe_invoke(handler, event)))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _safe_invoke(self, handler: EventHandler, event: MirrorEvent) -> None:
        try:
            await handler(event)
        except Exception as exc:
            logger.error("Error in event handler %s: %s", handler, exc, exc_info=True)

    @property
    def history(self) -> List[MirrorEvent]:
        return list(self._history)

    def clear(self) -> None:
        self._history.clear()
