"""
ml_classifier.py
Aegis Link Analyzer

Loads a pre-trained scikit-learn Random Forest model and generates
predictions with feature importance explanations.

Model file: app/ml/model.pkl
Train the model using: notebooks/train_classifier.ipynb (Google Colab)

If the model file is not present, the classifier returns a graceful
"model not loaded" response — the rest of the scan continues normally.
"""

import os
import pickle
import asyncio
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
from app.feature_extractor import (
    extract_features,
    extract_features_with_names,
    FEATURE_NAMES,
    FEATURE_COUNT,
)

MODEL_PATH = os.getenv("ML_MODEL_PATH", "/code/app/ml/model.pkl")

# Cached model — loaded once at startup
_model = None
_model_metadata: Dict = {}
_model_loaded: bool = False
_model_error: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# MODEL LOADING
# ─────────────────────────────────────────────────────────────────────────────

def load_model() -> Tuple[bool, str]:
    """
    Loads the trained model from disk into memory.
    Called once during application startup.

    Returns:
        (success: bool, message: str)
    """
    global _model, _model_metadata, _model_loaded, _model_error

    if not os.path.exists(MODEL_PATH):
        _model_error = (
            f"Model file not found at {MODEL_PATH}. "
            "Run the training notebook (notebooks/train_classifier.ipynb) "
            "to generate the model file."
        )
        _model_loaded = False
        return False, _model_error

    try:
        with open(MODEL_PATH, "rb") as f:
            saved = pickle.load(f)

        # Support both plain model and packaged dict {model, metadata}
        if isinstance(saved, dict) and "model" in saved:
            _model = saved["model"]
            _model_metadata = saved.get("metadata", {})
        else:
            _model = saved
            _model_metadata = {}

        # Validate feature count compatibility
        if hasattr(_model, "n_features_in_"):
            if _model.n_features_in_ != FEATURE_COUNT:
                raise ValueError(
                    f"Model expects {_model.n_features_in_} features, "
                    f"extractor produces {FEATURE_COUNT}. Retrain the model."
                )

        _model_loaded = True
        _model_error = None
        return True, f"Model loaded: {_model_metadata.get('model_type', type(_model).__name__)}"

    except Exception as e:
        _model_error = f"Failed to load model: {str(e)}"
        _model_loaded = False
        return False, _model_error


def is_model_loaded() -> bool:
    return _model_loaded


# ─────────────────────────────────────────────────────────────────────────────
# SYNCHRONOUS PREDICTION
# ─────────────────────────────────────────────────────────────────────────────

def _predict_sync(features: List[float]) -> Dict:
    """
    Runs the model prediction synchronously.
    Called via ThreadPoolExecutor to not block the async event loop.
    """
    import numpy as np

    if not _model_loaded or _model is None:
        return {"available": False, "error": _model_error}

    feature_array = np.array(features).reshape(1, -1)

    # Prediction: 0 = safe, 1 = phishing/malicious
    prediction = int(_model.predict(feature_array)[0])

    # Probability: [P(safe), P(malicious)]
    proba = _model.predict_proba(feature_array)[0]
    phishing_probability = float(proba[1]) if len(proba) > 1 else float(proba[0])
    safe_probability = float(proba[0])

    # Map to risk level
    if phishing_probability >= 0.75:
        ml_risk_level = "High Risk"
    elif phishing_probability >= 0.45:
        ml_risk_level = "Medium Risk"
    elif phishing_probability >= 0.20:
        ml_risk_level = "Low Risk"
    else:
        ml_risk_level = "Safe"

    # Feature importance (top contributing features)
    top_features = []
    if hasattr(_model, "feature_importances_"):
        importances = _model.feature_importances_
        feature_contributions = []
        for i, (imp, feat_val) in enumerate(zip(importances, features)):
            if feat_val > 0:  # Only show features that fired
                feature_contributions.append({
                    "feature": FEATURE_NAMES[i][0],
                    "description": FEATURE_NAMES[i][1],
                    "value": round(feat_val, 3),
                    "importance": round(float(imp), 4),
                    "contribution": round(float(imp) * feat_val, 4),
                })
        # Sort by contribution descending, take top 8
        top_features = sorted(
            feature_contributions,
            key=lambda x: x["contribution"],
            reverse=True
        )[:8]

    return {
        "available": True,
        "prediction": prediction,
        "ml_risk_level": ml_risk_level,
        "phishing_probability": round(phishing_probability * 100, 2),
        "safe_probability": round(safe_probability * 100, 2),
        "top_features": top_features,
        "model_type": _model_metadata.get("model_type", type(_model).__name__),
        "model_version": _model_metadata.get("version", "1.0"),
        "trained_on": _model_metadata.get("trained_on", "unknown"),
        "training_accuracy": _model_metadata.get("accuracy"),
        "features_used": FEATURE_COUNT,
    }


# ─────────────────────────────────────────────────────────────────────────────
# ASYNC WRAPPER
# ─────────────────────────────────────────────────────────────────────────────

async def run_ml_prediction(scan_result: Dict) -> Dict:
    """
    Extracts features from scan_result and runs the ML classifier.

    Returns a prediction dict that is included in the final scan response.
    If the model is not loaded, returns a graceful unavailable response.
    """
    if not _model_loaded:
        return {
            "available": False,
            "error": _model_error or "Model not loaded",
            "ml_risk_level": None,
            "phishing_probability": None,
            "top_features": [],
        }

    try:
        # Extract feature vector
        features = extract_features(scan_result)

        # Run prediction in thread pool (sklearn is CPU-bound)
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = await loop.run_in_executor(pool, _predict_sync, features)

        return result

    except Exception as e:
        return {
            "available": False,
            "error": f"ML prediction failed: {str(e)}",
            "ml_risk_level": None,
            "phishing_probability": None,
            "top_features": [],
        }
