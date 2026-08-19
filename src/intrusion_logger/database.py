"""Database access layer for intrusion_logger.

This module is intentionally limited to database operations.

Application-specific logic belongs in the modules above this layer:
    database.py  -> PostgreSQL access
    collector.py -> retrieving raw events
    models.py    -> application data structures
    processor.py -> processing/classification
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import psycopg
from psycopg import Connection
from psycopg.rows import dict_row

from intrusion_logger.config import DatabaseConfig


class DatabaseError(RuntimeError):
    """Base exception for database-related errors."""


class Database:
    """Small wrapper around a PostgreSQL connection.

    The Database class deliberately provides only generic database
    operations. It does not know about firewall logs, events,
    geolocation, or processing.
    """

    def __init__(self, config: DatabaseConfig) -> None:
        self.config = config
        self._connection: Connection | None = None

    def connect(self) -> None:
        """Open a connection to PostgreSQL.

        Raises
        ------
        DatabaseError
            If the connection cannot be established.
        """

        if self._connection is not None:
            return

        try:
            self._connection = psycopg.connect(
                host=self.config.host,
                port=self.config.port,
                dbname=self.config.database,
                user=self.config.user,
                password=self.config.password,
                row_factory=dict_row,
            )
        except psycopg.Error as exc:
            raise DatabaseError(
                "Unable to connect to PostgreSQL."
            ) from exc

    def close(self) -> None:
        """Close the current database connection."""

        if self._connection is not None:
            self._connection.close()
            self._connection = None

    @property
    def connection(self) -> Connection:
        """Return the active database connection.

        Raises
        ------
        DatabaseError
            If connect() has not been called.
        """

        if self._connection is None:
            raise DatabaseError(
                "Database is not connected. "
                "Call connect() first."
            )

        return self._connection

    def fetch_all(
        self,
        query: str,
        params: Sequence[Any] | Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a SELECT query and return all rows.

        Parameters
        ----------
        query:
            SQL query to execute.

        params:
            Parameters supplied to the SQL query.

        Returns
        -------
        list[dict[str, Any]]
            Query results as dictionaries.
        """

        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, params)
                return list(cursor.fetchall())

        except psycopg.Error as exc:
            raise DatabaseError(
                "Database query failed."
            ) from exc

    def fetch_one(
        self,
        query: str,
        params: Sequence[Any] | Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Execute a SELECT query and return one row."""

        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, params)
                return cursor.fetchone()

        except psycopg.Error as exc:
            raise DatabaseError(
                "Database query failed."
            ) from exc

    def execute(
        self,
        query: str,
        params: Sequence[Any] | Mapping[str, Any] | None = None,
    ) -> int:
        """Execute an INSERT, UPDATE, DELETE, or DDL statement.

        The transaction is committed after successful execution.

        Returns
        -------
        int
            Number of affected rows when PostgreSQL provides it.
        """

        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, params)
                affected_rows = cursor.rowcount

            self.connection.commit()

            return affected_rows

        except psycopg.Error as exc:
            self.connection.rollback()

            raise DatabaseError(
                "Database statement failed."
            ) from exc

    def __enter__(self) -> Database:
        """Allow Database to be used as a context manager."""

        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: Any,
    ) -> None:
        """Close the database when leaving a context manager."""

        self.close()


def connect(config: DatabaseConfig) -> Database:
    """Create and connect a Database instance."""

    database = Database(config)
    database.connect()
    return database