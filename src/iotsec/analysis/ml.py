"""Unsupervised behaviour model (Isolation Forest).

The model does not look at raw volumes - a smart TV moves more data in a
minute than a thermostat does in a week. Each window is first expressed as
its deviation from the device's own learned baseline (a z-score per
feature), and one Isolation Forest learns what normal deviation looks like
across all devices. That way devices with little history are still covered
and nothing is compared against a different kind of device.

The bundle is written with a detached signature and is only unpickled after
the signature verifies, because loading a joblib file can execute code.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import os
import time
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from .baseline import Baseline
from .features import FEATURES

log = logging.getLogger(__name__)
MODEL_VERSION = 2
Z_CLIP = 1000.0


def deviation_vector(features: dict[str, float], baseline: Baseline) -> np.ndarray:
    z = np.array([baseline.zscore(name, float(features.get(name, 0.0))) for name in FEATURES])
    z = np.clip(z, -Z_CLIP, Z_CLIP)
    return np.sign(z) * np.log1p(np.abs(z))  # compress: 5 sigma and 500 sigma both stand out


class AnomalyModel:
    def __init__(self, model: IsolationForest | None = None, metadata: dict | None = None,
                 margin: float = 0.0) -> None:
        self.model = model
        self.metadata = metadata or {}
        self.margin = margin

    @classmethod
    def train(cls, windows_by_device: dict[str, list[dict[str, float]]],
              baselines: dict[str, Baseline], min_windows: int, contamination: float,
              seed: int = 42) -> AnomalyModel:
        vectors = [deviation_vector(features, baselines[mac])
                   for mac, windows in windows_by_device.items() if mac in baselines
                   for features in windows[:5000]]
        metadata = {"version": MODEL_VERSION, "trained_at": time.time(),
                    "devices": len(windows_by_device), "windows": len(vectors),
                    "sklearn_version": sklearn.__version__}
        if len(vectors) < min_windows:
            return cls(None, metadata)
        matrix = np.vstack(vectors)
        model = IsolationForest(n_estimators=200, contamination=contamination,
                                random_state=seed).fit(matrix)
        return cls(model, metadata)

    @property
    def ready(self) -> bool:
        return self.model is not None

    def score(self, features: dict[str, float], baseline: Baseline) -> tuple[float | None, bool]:
        """Return (anomaly score, is_anomalous). Positive scores are anomalous."""
        if self.model is None:
            return None, False
        vector = deviation_vector(features, baseline).reshape(1, -1)
        score = float(-self.model.decision_function(vector)[0])
        return round(score, 4), score > self.margin

    # ------------------------------------------------------------ persistence
    @staticmethod
    def _digest(data: bytes, key: str) -> tuple[str, str]:
        if key:
            return "hmac-sha256", hmac.new(key.encode(), data, hashlib.sha256).hexdigest()
        return "sha256", hashlib.sha256(data).hexdigest()

    def save(self, path: str | Path, signing_key: str = "") -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        buffer = io.BytesIO()
        joblib.dump({"model": self.model, "metadata": self.metadata}, buffer)
        data = buffer.getvalue()
        algorithm, digest = self._digest(data, signing_key)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)  # atomic swap: readers never see a partial file
        sig = _sig_path(path)
        sig.write_text(json.dumps({"algorithm": algorithm, "digest": digest}), encoding="utf-8")
        os.chmod(sig, 0o600)

    @classmethod
    def load(cls, path: str | Path, signing_key: str = "",
             margin: float = 0.0) -> AnomalyModel | None:
        path = Path(path)
        if not path.exists():
            return None
        data = path.read_bytes()
        try:
            signature = json.loads(_sig_path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            log.error("model %s has no valid signature; refusing to load it", path)
            return None
        algorithm, expected = cls._digest(data, signing_key)
        if signature.get("algorithm") != algorithm or not hmac.compare_digest(
                str(signature.get("digest", "")), expected):
            log.error("signature check failed for model %s; refusing to load it", path)
            return None
        bundle = joblib.load(io.BytesIO(data))
        if bundle.get("metadata", {}).get("version") != MODEL_VERSION:
            log.warning("model %s has an old format; retrain it", path)
            return None
        return cls(bundle["model"], bundle["metadata"], margin)


def _sig_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".sig")
