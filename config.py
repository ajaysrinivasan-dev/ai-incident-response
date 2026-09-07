import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
CHECKPOINT_DB = Path(
    os.getenv(
        "INCIDENT_CHECKPOINT_DB",
        str(BASE_DIR / "incident_checkpoints.db"),
    )
)
