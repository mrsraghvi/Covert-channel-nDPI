"""
ml_detector.py
Online Isolation Forest anomaly scorer over the 21-dim feature vector.
Refits periodically once enough samples have accumulated, so the model
adapts to the specific network's baseline traffic.
"""
from __future__ import annotations

import logging
import os
import tempfile
import threading
from collections import deque
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from feature_extractor import FlowFeatures

log = logging.getLogger("covertscope.ml_detector")


class MLDetector:
    _STATE_VERSION = 1

    def __init__(
        self,
        window_size: int = 2000,
        min_train_samples: int = 50,
        refit_every: int = 100,
        contamination: float = 0.05,
        model_path: str | Path | None = None,
    ):
        self.window: deque[list[float]] = deque(maxlen=window_size)
        self.window_size = window_size
        self.min_train_samples = min_train_samples
        self.refit_every = refit_every
        self.contamination = contamination
        self._since_refit = 0
        self._lock = threading.Lock()
        self.model: IsolationForest | None = None
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.model_path = Path(
            model_path
            if model_path is not None
            else os.getenv(
                "COVERTSCOPE_ML_MODEL_PATH",
                Path(__file__).resolve().parent / ".data" / "ml_detector.joblib",
            )
        )
        self._load()

    def _fit(self):
        X = np.array(self.window)
        self.scaler.fit(X)
        Xs = self.scaler.transform(X)
        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(Xs)
        self.is_fitted = True
        self._since_refit = 0
        self._save()

    def _state(self) -> dict[str, Any]:
        return {
            "state_version": self._STATE_VERSION,
            "feature_names": FlowFeatures.feature_names(),
            "window": list(self.window),
            "since_refit": self._since_refit,
            "min_train_samples": self.min_train_samples,
            "refit_every": self.refit_every,
            "contamination": self.contamination,
            "model": self.model,
            "scaler": self.scaler,
        }

    def _save(self) -> None:
        if not self.is_fitted or self.model is None:
            return

        temporary_path: str | None = None
        try:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                dir=self.model_path.parent,
                prefix=f".{self.model_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = temporary_file.name
            joblib.dump(self._state(), temporary_path)
            os.replace(temporary_path, self.model_path)
        except OSError:
            log.exception("Could not persist Isolation Forest state to %s", self.model_path)
        except Exception:
            log.exception("Could not serialize Isolation Forest state to %s", self.model_path)
        finally:
            if temporary_path and os.path.exists(temporary_path):
                try:
                    os.unlink(temporary_path)
                except OSError:
                    log.exception("Could not remove temporary model file %s", temporary_path)

    def _load(self) -> None:
        if not self.model_path.is_file():
            return

        try:
            state = joblib.load(self.model_path)
            expected_features = FlowFeatures.feature_names()
            if (
                not isinstance(state, dict)
                or state.get("state_version") != self._STATE_VERSION
                or state.get("feature_names") != expected_features
                or not isinstance(state.get("model"), IsolationForest)
                or not isinstance(state.get("scaler"), StandardScaler)
                or getattr(state["model"], "n_features_in_", None) != len(expected_features)
                or getattr(state["scaler"], "n_features_in_", None) != len(expected_features)
            ):
                raise ValueError("persisted model format or feature schema is incompatible")

            window = state.get("window")
            if not isinstance(window, list) or any(
                not isinstance(vector, list)
                or len(vector) != len(expected_features)
                or not np.isfinite(vector).all()
                for vector in window
            ):
                raise ValueError("persisted training window is invalid")

            self.window = deque(window[-self.window_size :], maxlen=self.window_size)
            self._since_refit = int(state["since_refit"])
            self.min_train_samples = int(state["min_train_samples"])
            self.refit_every = int(state["refit_every"])
            self.contamination = float(state["contamination"])
            self.model = state["model"]
            self.scaler = state["scaler"]
            self.is_fitted = True
            log.info("loaded persisted Isolation Forest state from %s", self.model_path)
        except Exception:
            log.exception(
                "Could not load persisted Isolation Forest state from %s; starting with a fresh model",
                self.model_path,
            )
            self.window.clear()
            self._since_refit = 0
            self.model = None
            self.scaler = StandardScaler()
            self.is_fitted = False

    def score(self, features: FlowFeatures) -> float:
        """Return anomaly score in [0, 1], higher = more anomalous.
        Also updates the training window and refits periodically."""
        vec = features.to_vector()

        with self._lock:
            self.window.append(vec)
            self._since_refit += 1

            if len(self.window) < self.min_train_samples:
                return 0.0

            if not self.is_fitted or self._since_refit >= self.refit_every:
                self._fit()

            if not self.is_fitted or self.model is None:
                return 0.0

            Xs = self.scaler.transform([vec])
            # decision_function: higher = more normal. Convert to 0..1 anomaly score.
            raw = self.model.decision_function(Xs)[0]
            # squash roughly into [0,1] via sigmoid centered at 0
            anomaly = 1 / (1 + np.exp(raw * 6))
            return float(np.clip(anomaly, 0.0, 1.0))

    def feature_importance_proxy(self) -> dict[str, float]:
        """Isolation Forest has no native feature_importances_; approximate
        by std-dev of each scaled feature across the current window (higher
        spread = more discriminative for this traffic mix)."""
        if len(self.window) < self.min_train_samples:
            return {}
        X = np.array(self.window)
        stds = X.std(axis=0)
        names = FlowFeatures.feature_names()
        total = stds.sum() or 1.0
        return {n: float(s / total) for n, s in zip(names, stds)}
