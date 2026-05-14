"""Backend package initializer.

Loads environment variables from `.env` files so local development can run
without manually exporting variables.
"""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


_BACKEND_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _BACKEND_DIR.parent

# Prefer project-root .env, but also allow backend/.env for convenience.
load_dotenv(_PROJECT_ROOT / ".env", override=False)
load_dotenv(_BACKEND_DIR / ".env", override=False)
