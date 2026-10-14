from __future__ import annotations

import json
from pathlib import Path

import pytest

VECTORS_PATH = Path(__file__).parent / "vectors" / "vectors.json"


@pytest.fixture(scope="session")
def vectors() -> dict:
    """Cross-language vectors produced by running the TypeScript SDK."""
    with VECTORS_PATH.open(encoding="utf-8") as f:
        return json.load(f)
