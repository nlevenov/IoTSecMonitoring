from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from iotsec.config import Settings, load_settings
from iotsec.simulate import generate, write

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    result = load_settings(ROOT / "config" / "lab.yaml")
    result.database = str(tmp_path / "test.db")
    result.model_path = str(tmp_path / "model.joblib")
    result.feeds_dir = str(ROOT / "feeds")
    return result


@pytest.fixture(scope="session")
def lab_pcap(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One simulated capture shared by the end-to-end tests (seed differs from the demo)."""
    path = tmp_path_factory.mktemp("lab") / "lab.pcap"
    write(generate(start=1_760_000_000, learning_minutes=36, attack_minutes=30, seed=11), path)
    return path


requires_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark missing")
