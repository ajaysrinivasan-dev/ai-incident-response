from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
CHECKPOINT_DB = BASE_DIR / "incident_checkpoints.db"


def _get_connection() -> sqlite3.Connection:
    """Create a short-lived SQLite connection."""
    connection = sqlite3.connect(str(CHECKPOINT_DB))
    connection.row_factory = sqlite3.Row
    return connection


def _utc_now() -> str:
    """Return the current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def initialize_metadata_table() -> None:
    """Create the investigation metadata table if it does not exist."""
    with _get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                thread_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                scenario TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        connection.commit()


def create_investigation(
    thread_id: str,
    title: str,
    scenario: str,
    severity: str,
    status: str = "Running",
) -> bool:
    """Create metadata for a new investigation."""
    now = _utc_now()

    try:
        with _get_connection() as connection:
            connection.execute(
                """
                INSERT INTO investigations (
                    thread_id,
                    title,
                    scenario,
                    severity,
                    status,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    thread_id,
                    title,
                    scenario,
                    severity,
                    status,
                    now,
                    now,
                ),
            )

            connection.commit()

        return True

    except sqlite3.IntegrityError:
        return False


def update_investigation(
    thread_id: str,
    *,
    title: str | None = None,
    scenario: str | None = None,
    severity: str | None = None,
    status: str | None = None,
) -> bool:
    """Update supplied investigation metadata fields."""
    fields: list[str] = []
    values: list[Any] = []

    if title is not None:
        fields.append("title = ?")
        values.append(title)

    if scenario is not None:
        fields.append("scenario = ?")
        values.append(scenario)

    if severity is not None:
        fields.append("severity = ?")
        values.append(severity)

    if status is not None:
        fields.append("status = ?")
        values.append(status)

    if not fields:
        return False

    fields.append("updated_at = ?")
    values.append(_utc_now())
    values.append(thread_id)

    try:
        with _get_connection() as connection:
            cursor = connection.execute(
                f"""
                UPDATE investigations
                SET {", ".join(fields)}
                WHERE thread_id = ?
                """,
                values,
            )

            connection.commit()

            return cursor.rowcount > 0

    except sqlite3.Error:
        return False


def get_investigations() -> list[dict[str, Any]]:
    """Return saved investigations ordered by most recently updated."""
    initialize_metadata_table()

    try:
        with _get_connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    thread_id,
                    title,
                    scenario,
                    severity,
                    status,
                    created_at,
                    updated_at
                FROM investigations
                ORDER BY updated_at DESC
                """
            ).fetchall()

        return [dict(row) for row in rows]

    except sqlite3.Error:
        return []


def get_investigation(thread_id: str) -> dict[str, Any] | None:
    """Return metadata for one investigation."""
    initialize_metadata_table()

    try:
        with _get_connection() as connection:
            row = connection.execute(
                """
                SELECT
                    thread_id,
                    title,
                    scenario,
                    severity,
                    status,
                    created_at,
                    updated_at
                FROM investigations
                WHERE thread_id = ?
                """,
                (thread_id,),
            ).fetchone()

        return dict(row) if row else None

    except sqlite3.Error:
        return None


def get_saved_threads() -> list[str]:
    """Return checkpoint thread IDs ordered by latest checkpoint."""
    if not CHECKPOINT_DB.exists():
        return []

    try:
        with _get_connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    thread_id
                FROM checkpoints
                GROUP BY thread_id
                ORDER BY MAX(checkpoint_id) DESC
                """
            ).fetchall()

        return [row["thread_id"] for row in rows]

    except sqlite3.Error:
        return []


def checkpoint_database_exists() -> bool:
    """Return whether the checkpoint database exists."""
    return CHECKPOINT_DB.exists()


def delete_investigation(thread_id: str) -> bool:
    """
    Delete investigation metadata and its LangGraph checkpoint data.

    This removes the investigation from the local application's
    saved investigation history.
    """
    if not CHECKPOINT_DB.exists():
        return False

    try:
        with _get_connection() as connection:
            connection.execute(
                """
                DELETE FROM investigations
                WHERE thread_id = ?
                """,
                (thread_id,),
            )

            connection.execute(
                """
                DELETE FROM checkpoints
                WHERE thread_id = ?
                """,
                (thread_id,),
            )

            connection.execute(
                """
                DELETE FROM writes
                WHERE thread_id = ?
                """,
                (thread_id,),
            )

            connection.commit()

        return True

    except sqlite3.Error:
        return False


def archive_investigation(thread_id: str) -> bool:
    """Mark an investigation as archived without deleting its data."""
    return update_investigation(
        thread_id,
        status="Archived",
    )


initialize_metadata_table()
