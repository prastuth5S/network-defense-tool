"""train_ml.py - train the anomaly model on baseline (normal) traffic features.

Usage:
  pip install scikit-learn joblib numpy
  python train_ml.py
"""
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from network_defense.detections.ml_anomaly import FEATURES

X = np.loadtxt("data/baseline_features.csv", delimiter=",", skiprows=1)
print(f"Training on {len(X)} windows, features: {FEATURES}")

model = IsolationForest(n_estimators=200, contamination=0.01, random_state=42).fit(X)

Path("models").mkdir(exist_ok=True)
joblib.dump(model, "models/anomaly.joblib")
print("Saved models/anomaly.joblib")
