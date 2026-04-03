import os
import logging
import numpy as np
import joblib
from collections import defaultdict
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

MODEL_PATH = Path("/app/data/models/isolation_forest.pkl")


class AnomalyDetector:
    """
    Isolation Forest based anomaly detector.
    Trains on normal traffic and flags deviations.
    """

    def __init__(self):
        self.model = None
        self._ip_stats: dict = defaultdict(lambda: {
            "request_count": 0,
            "get_count": 0,
            "post_count": 0,
            "error_count": 0,
            "total_size": 0,
            "user_agents": set(),
            "first_seen": datetime.utcnow().timestamp(),
        })
        self._load_model()

    def _load_model(self):
        if MODEL_PATH.exists():
            try:
                self.model = joblib.load(MODEL_PATH)
                logger.info("Anomaly model loaded from disk.")
            except Exception as e:
                logger.warning(f"Could not load anomaly model: {e}")

    def _save_model(self):
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, MODEL_PATH)

    def _extract_features(self, ip: str, request: dict) -> np.ndarray:
        stats = self._ip_stats[ip]
        now = datetime.utcnow()
        hour = now.hour
        day_of_week = now.weekday()

        features = [
            stats["request_count"],
            stats["get_count"],
            stats["post_count"],
            stats["error_count"],
            stats["total_size"] / max(stats["request_count"], 1),
            len(stats["user_agents"]),
            len(request.get("path", "")),
            hour,
            day_of_week,
            request.get("status", 200),
        ]
        return np.array(features, dtype=float).reshape(1, -1)

    def update_stats(self, request: dict):
        ip = request.get("ip", "")
        stats = self._ip_stats[ip]
        stats["request_count"] += 1
        method = request.get("method", "GET")
        if method == "GET":
            stats["get_count"] += 1
        elif method == "POST":
            stats["post_count"] += 1
        if request.get("status", 200) >= 400:
            stats["error_count"] += 1
        stats["total_size"] += request.get("size", 0)
        ua = request.get("user_agent", "")
        if ua:
            stats["user_agents"].add(ua)

    def train(self, requests: list):
        """Train on a batch of normal requests."""
        from sklearn.ensemble import IsolationForest

        if len(requests) < 50:
            logger.info("Not enough data to train anomaly model.")
            return

        X = []
        for req in requests:
            self.update_stats(req)
            ip = req.get("ip", "")
            X.append(self._extract_features(ip, req).flatten())

        X = np.array(X)
        self.model = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
        self.model.fit(X)
        self._save_model()
        logger.info(f"Anomaly model trained on {len(X)} samples.")

    def detect(self, request: dict) -> dict:
        ip = request.get("ip", "")
        self.update_stats(request)

        if self.model is None:
            return {"detected": False}

        features = self._extract_features(ip, request)
        score = self.model.decision_function(features)[0]
        prediction = self.model.predict(features)[0]

        # -1 = anomaly, 1 = normal
        if prediction == -1:
            anomaly_score = max(0.0, min(1.0, -score))
            return {
                "detected": True,
                "attack_type": "ANOMALY",
                "severity": "MEDIUM" if anomaly_score < 0.7 else "HIGH",
                "confidence": round(anomaly_score, 3),
                "recommended_action": "ALERT_ONLY",
                "details": f"Anomalous traffic pattern from {ip} (score={score:.3f})",
            }

        return {"detected": False}
