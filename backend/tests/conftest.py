import os
from pathlib import Path

os.environ.setdefault("REDPATH_API_KEYS", "test-token:soc_lead")
os.environ.setdefault("DATABASE_URL", "sqlite:///./data/test-redpath.db")
Path("data/test-redpath.db").unlink(missing_ok=True)
