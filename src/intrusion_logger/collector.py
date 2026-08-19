"""Collect raw firewall events from PostgreSQL."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any

from .database import Database
from .models import FirewallEvent


class CollectorError(RuntimeError):
    """Raised when firewall events cannot be collected."""


class FirewallLogCollector:
    """Retrieve raw firewall log records from PostgreSQL.

    This class is responsible for:
        - querying the firewall log table
        - converting database rows into FirewallEvent objects

    It is not responsible for:
        - opening database connections
        - geolocation
        - event classification
        - enrichment
        - writing data back to PostgreSQL
    """

    def __init__(
        self,
        database: Database,
        config: Any,
    ) -> None:
        self.database = database
        self.config = config

    def fetch_unprocessed(self) -> list[FirewallEvent]:
        """Fetch a batch of firewall events.

        Events are currently returned in ascending ID order.

        TODO:
            Define how an event becomes "processed". The planned
            enrichment table keyed by firewall_logs.id can eventually
            be used to exclude events that have already been handled.

        Returns
        -------
        list[FirewallEvent]
            Raw firewall events converted into application models.
        """

        sql = f"""
            SELECT
                id,
                log_time,
                src_ip,
                dst_ip,
                protocol,
                spt,
                dport,
                action,
                message
            FROM {self.config.schema}.{self.config.table}
            ORDER BY id
            LIMIT %s
        """

        try:
            rows = self.database.fetch_all(
                sql,
                (self.config.batch_size,),
            )
        except Exception as exc:
            raise CollectorError(
                "Unable to collect firewall events."
            ) from exc

        return [
            self._row_to_event(row)
            for row in rows
        ]

    @staticmethod
    def _row_to_event(
        row: dict[str, Any],
    ) -> FirewallEvent:
        """Convert a database row into a FirewallEvent."""

        try:
            return FirewallEvent(
                id=row["id"],
                log_time=row["log_time"],
                src_ip=ip_address(
                    str(row["src_ip"])
                ),
                dst_ip=(
                    ip_address(str(row["dst_ip"]))
                    if row["dst_ip"] is not None
                    else None
                ),
                protocol=row["protocol"],
                src_port=row["spt"],
                dst_port=row["dport"],
                action=row["action"],
                message=row["message"],
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise CollectorError(
                "Invalid firewall log database row."
            ) from exc