from pathlib import Path
import sqlite3


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

CHECKPOINT_DB = BASE_DIR / "incident_checkpoints.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================


def get_connection():
    """
    Create a SQLite connection to the LangGraph checkpoint database.
    """

    return sqlite3.connect(str(CHECKPOINT_DB))


# ============================================================
# CHECK DATABASE
# ============================================================


def checkpoint_database_exists() -> bool:
    """
    Check whether the LangGraph checkpoint database exists.
    """

    return CHECKPOINT_DB.exists()


# ============================================================
# GET SAVED THREADS
# ============================================================


def get_saved_threads() -> list[str]:
    """
    Return saved LangGraph investigation thread IDs.

    Investigations are ordered from newest to oldest based on
    their latest checkpoint.
    """

    if not checkpoint_database_exists():
        return []

    query = """
        SELECT
            thread_id,
            MAX(checkpoint_id) AS latest_checkpoint
        FROM checkpoints
        WHERE thread_id IS NOT NULL
        GROUP BY thread_id
        ORDER BY latest_checkpoint DESC
    """

    try:
        with get_connection() as connection:
            cursor = connection.execute(query)

            rows = cursor.fetchall()

        return [row[0] for row in rows if row[0]]

    except sqlite3.Error as exc:
        print(f"Could not read saved investigations: {exc}")

        return []


# ============================================================
# DELETE SAVED THREAD
# ============================================================


def delete_saved_thread(thread_id: str) -> bool:
    """
    Delete a saved investigation from the checkpoint database.

    This function is provided for future UI functionality.
    """

    if not checkpoint_database_exists():
        return False

    if not thread_id:
        return False

    try:
        with get_connection() as connection:
            connection.execute(
                """
                DELETE FROM checkpoints
                WHERE thread_id = ?
                """,
                (thread_id,),
            )

            connection.commit()

        return True

    except sqlite3.Error as exc:
        print(f"Could not delete investigation: {exc}")

        return False
