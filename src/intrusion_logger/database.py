"""Database access layer for intrusion_logger.

This module is intentionally limited to database operations.

Application-specific logic belongs in the modules above this layer:
    database.py  -> PostgreSQL access
    collector.py -> retrieving raw events
    models.py    -> application data structures
    processor.py -> processing/classification
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any

import psycopg
from psycopg import Connection
from psycopg.rows import dict_row

from intrusion_logger.config import DatabaseConfig

logger = logging.getLogger(__name__)


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
            logger.debug("Database connection already established")
            return

        logger.info(f"Connecting to PostgreSQL at {self.config.host}:{self.config.port}/{self.config.database}")
        try:
            self._connection = psycopg.connect(
                host=self.config.host,
                port=self.config.port,
                dbname=self.config.database,
                user=self.config.user,
                password=self.config.password,
                row_factory=dict_row,
            )
            logger.info("Successfully connected to PostgreSQL")
        except psycopg.Error as exc:
            logger.error(f"Failed to connect to PostgreSQL: {exc}")
            raise DatabaseError(
                "Unable to connect to PostgreSQL."
            ) from exc

    def close(self) -> None:
        """Close the current database connection."""

        if self._connection is not None:
            logger.info("Closing database connection")
            self._connection.close()
            self._connection = None
            logger.debug("Database connection closed")

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

        logger.debug(f"Executing fetch_all query: {query[:100]}...")
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, params)
                results = list(cursor.fetchall())
                logger.debug(f"fetch_all returned {len(results)} rows")
                return results

        except psycopg.Error as exc:
            logger.error(f"fetch_all query failed: {exc}")
            raise DatabaseError(
                "Database query failed."
            ) from exc

    def fetch_one(
        self,
        query: str,
        params: Sequence[Any] | Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Execute a SELECT query and return one row."""

        logger.debug(f"Executing fetch_one query: {query[:100]}...")
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, params)
                result = cursor.fetchone()
                logger.debug(f"fetch_one returned {result is not None}")
                return result

        except psycopg.Error as exc:
            logger.error(f"fetch_one query failed: {exc}")
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

        logger.debug(f"Executing execute statement: {query[:100]}...")
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, params)
                affected_rows = cursor.rowcount

            self.connection.commit()
            logger.info(f"Execute statement affected {affected_rows} rows")

            return affected_rows

        except psycopg.Error as exc:
            self.connection.rollback()
            logger.error(f"Execute statement failed, transaction rolled back: {exc}")

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