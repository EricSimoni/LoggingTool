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
        self._ensure_connected()

    def _ensure_connected(self) -> None:
        """Ensure database connection is established."""
        if self.database._connection is None:
            self.database.connect()

    def close(self) -> None:
        """Close the database connection."""
        self.database.close()

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

    def dump_all_logs(self) -> dict[int, dict[str, Any]]:
        """Dump all firewall logs to a dictionary.

        Returns
        -------
        dict[int, dict[str, Any]]
            Dictionary mapping log IDs to log data.
        """
        sql = f"SELECT * FROM {self.config.schema}.{self.config.table}"
        rows = self.database.fetch_all(sql)
        
        firewall_log_dict = {}
        for row in rows:
            firewall_log_dict[row["id"]] = {
                "log_time": row["log_time"],
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "spt": row["spt"],
                "dport": row["dport"],
                "protocol": row["protocol"],
                "action": row["action"],
            }
        
        return firewall_log_dict

    def count_table_rows(self, table_name: str) -> int:
        """Count rows in a specified table.

        Parameters
        ----------
        table_name: str
            Name of the table to count rows in.

        Returns
        -------
        int
            Number of rows in the table.
        """
        sql = f"SELECT count(*) as row_count FROM {table_name}"
        result = self.database.fetch_one(sql)
        return result["row_count"]