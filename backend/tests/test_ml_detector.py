from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.engine import MLDetector
from feature_extractor import FlowFeatures


def sample_features(value: float) -> FlowFeatures:
    return FlowFeatures(
        iat_mean=value,
        iat_variance=value * 2,
        iat_cv=value / 10,
        packets=int(value * 10),
        bytes=int(value * 100),
        duration_ms=int(value * 1000),
        payload_entropy=value / 2,
        dns_qps=value / 3,
    )


class MLDetectorPersistenceTests(unittest.TestCase):
    def test_fitted_model_and_training_window_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            model_path = Path(directory) / "model.joblib"
            detector = MLDetector(
                min_train_samples=5,
                refit_every=100,
                contamination=0.1,
                model_path=model_path,
            )
            for value in range(1, 6):
                detector.score(sample_features(float(value)))

            self.assertTrue(model_path.is_file())
            self.assertTrue(detector.is_fitted)

            restored = MLDetector(model_path=model_path)
            self.assertTrue(restored.is_fitted)
            self.assertEqual(list(restored.window), list(detector.window))
            self.assertEqual(restored.min_train_samples, 5)
            self.assertEqual(restored.refit_every, 100)
            self.assertEqual(restored.contamination, 0.1)
            self.assertEqual(
                restored.score(sample_features(6.0)),
                detector.score(sample_features(6.0)),
            )

    def test_missing_model_starts_with_an_untrained_detector(self):
        with tempfile.TemporaryDirectory() as directory:
            detector = MLDetector(model_path=Path(directory) / "missing.joblib")

        self.assertFalse(detector.is_fitted)
        self.assertIsNone(detector.model)
        self.assertEqual(len(detector.window), 0)

    def test_corrupt_model_is_reported_and_starts_fresh(self):
        with tempfile.TemporaryDirectory() as directory:
            model_path = Path(directory) / "corrupt.joblib"
            model_path.write_bytes(b"not a joblib model")

            with self.assertLogs("covertscope.ml_detector", level="ERROR"):
                detector = MLDetector(model_path=model_path)

        self.assertFalse(detector.is_fitted)
        self.assertIsNone(detector.model)
        self.assertEqual(len(detector.window), 0)


if __name__ == "__main__":
    unittest.main()
