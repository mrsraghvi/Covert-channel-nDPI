"""
ml_detector.py
Online Isolation Forest anomaly scorer over the 21-dim feature vector.
Refits periodically once enough samples have accumulated, so the model
adapts to the specific network's baseline traffic.
"""
from __future__ import annotations

import threading
from collections import deque

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from feature_extractor import FlowFeatures


class MLDetector:
    def __init__(
        self,
        window_size: int = 2000,
        min_train_samples: int = 50,
        refit_every: int = 100,
        contamination: float = 0.05,
    ):
        self.window: deque[list[float]] = deque(maxlen=window_size)
        self.min_train_samples = min_train_samples
        self.refit_every = refit_every
        self.contamination = contamination
        self._since_refit = 0
        self._lock = threading.Lock()
        self.model: IsolationForest | None = None
        self.scaler = StandardScaler()
        self.is_fitted = False

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
                self._since_refit = 0

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
