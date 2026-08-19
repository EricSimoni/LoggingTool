"""Process and enrich firewall events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .geolocation import GeoLocator
from .models import FirewallEvent, GeoLocation


class ProcessingError(RuntimeError):
    """Raised when an event cannot be processed."""


@dataclass(slots=True)
class ProcessedEvent:
    """Result of processing a FirewallEvent.

    This is intentionally small for now. Additional fields for
    classification, severity, scanner detection, and other
    enrichment can be added as the processing pipeline develops.
    """

    event_id: int

    src_ip: str
    dst_ip: str | None

    protocol: str | None

    src_port: int | None
    dst_port: int | None

    action: str | None

    geo: GeoLocation | None


class EventProcessor:
    """Process firewall events.

    Currently this processor only performs GeoIP enrichment.

    Future responsibilities may include:
        - identifying repeated scanners
        - classifying ports and protocols
        - assigning severity
        - additional event enrichment
    """

    def __init__(
        self,
        geolocator: GeoLocator,
    ) -> None:
        self.geolocator = geolocator

    def process_event(
        self,
        event: FirewallEvent,
    ) -> ProcessedEvent:
        """Process a single firewall event."""

        try:
            location = self.geolocator.lookup(
                event.src_ip
            )

            return ProcessedEvent(
                event_id=event.id,
                src_ip=str(event.src_ip),
                dst_ip=(
                    str(event.dst_ip)
                    if event.dst_ip
                    else None
                ),
                protocol=event.protocol,
                src_port=event.src_port,
                dst_port=event.dst_port,
                action=event.action,
                geo=location,
            )

        except Exception as exc:
            raise ProcessingError(
                f"Unable to process event {event.id}."
            ) from exc

    def process_events(
        self,
        events: list[FirewallEvent],
    ) -> list[ProcessedEvent]:
        """Process a collection of firewall events."""

        return [
            self.process_event(event)
            for event in events
        ]