"""Vercel serverless entrypoint — exposes the FastAPI ASGI app.

Vercel runs each file under ``api/`` as a serverless function; ``vercel.json``
rewrites every route to this one so FastAPI keeps owning its ``/api/...`` paths.
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.main import app  # noqa: E402

__all__ = ["app"]
