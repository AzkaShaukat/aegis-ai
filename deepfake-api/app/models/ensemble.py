"""
Ensemble loading and inference — Phase 3.

confidence_pct formula: conviction + (1-conviction)*0.25
  - conviction = max(p_fake, 1-p_fake)  [always 0.5→1.0]
  - GUARANTEED: confidence >= conviction * 100
  - p_fake=0.83 → confidence=87.2%  (always ≥ 83%)
  - p_fake=0.67 → confidence=75.2%  (always ≥ 67%)
  - p_fake=0.08 → conviction=0.92 → confidence=94%  (always ≥ 92%)
"""
from __future__ import annotations
import json, logging, math, os
from dataclasses import dataclass, field
from typing import Optional

import torch
import torch.nn as nn

from app.config import get_settings
from app.models.image_models import DeepfakeEfficientNetB4, DeepfakeViT, DeepfakeFreqCNN
from app.models.video_models import SpatialCNN, TemporalTransformer, FrequencySRMCNN

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass
class ModelLoadStatus:
    loaded: bool
    path: str
    error: Optional[str] = None


@dataclass
class EnsembleState:
    model_1: Optional[nn.Module]
    model_2: Optional[nn.Module]
    model_3: Optional[nn.Module]
    weights: list
    weight_source: str
    statuses: dict = field(default_factory=dict)
    device: str = "cpu"
    decision_threshold: float = 0.5

    @property
    def any_loaded(self) -> bool:
        return any(m is not None for m in [self.model_1, self.model_2, self.model_3])

    @property
    def all_loaded(self) -> bool:
        return all(m is not None for m in [self.model_1, self.model_2, self.model_3])


def _resolve_device() -> str:
    cfg = settings.DEVICE
    if cfg == "auto":
        return "cuda" if torch.cuda.is_available() else "cpu"
    return cfg


def remap_freqcnn_keys(state_dict: dict) -> dict:
    new = {}
    for k, v in state_dict.items():
        k = k.replace("stage1","s1").replace("stage2","s2")
        k = k.replace("stage3","s3").replace("stage4","s4")
        k = k.replace("branch1","b1").replace("branch3","b3").replace("branch5","b5")
        k = k.replace("shortcut","skip")
        new[k] = v
    return new


def _load_checkpoint(path, model, device, is_freqcnn=False):
    if not os.path.exists(path):
        return False, f"File not found: {path}"
    try:
        ckpt = torch.load(path, map_location=device, weights_only=False)
        if isinstance(ckpt, dict):
            sd = (ckpt.get("model_state") or ckpt.get("model_state_dict")
                  or ckpt.get("state_dict") or ckpt.get("model") or ckpt)
        else:
            return False, f"Unexpected format: {type(ckpt)}"
        sd = {k.replace("module.", ""): v for k, v in sd.items()}
        if is_freqcnn:
            sd = remap_freqcnn_keys(sd)
        model.load_state_dict(sd, strict=False)
        model.eval()
        logger.info(f"Loaded: {path}")
        return True, None
    except Exception as e:
        return False, str(e)


def _load_image_config(path):
    if not os.path.exists(path):
        return None, 0.5
    try:
        cfg = json.load(open(path))
        w = cfg.get("weights", {})
        if isinstance(w, dict):
            weights = [
                float(w.get("efficientnet", settings.IMAGE_DEFAULT_WEIGHTS[0])),
                float(w.get("vit",          settings.IMAGE_DEFAULT_WEIGHTS[1])),
                float(w.get("freqcnn",      settings.IMAGE_DEFAULT_WEIGHTS[2])),
            ]
        elif isinstance(w, list) and len(w) == 3:
            weights = [float(x) for x in w]
        else:
            return None, 0.5
        t = sum(weights)
        return [x/t for x in weights], float(cfg.get("threshold", 0.5))
    except Exception as e:
        logger.warning(f"Image config failed: {e}")
        return None, 0.5


def _load_video_config(path):
    if not os.path.exists(path):
        return None, 0.5
    try:
        cfg = json.load(open(path))
        w = cfg.get("weights", {})
        if isinstance(w, dict):
            weights = [
                float(w.get("spatial",   settings.VIDEO_DEFAULT_WEIGHTS[0])),
                float(w.get("frequency", settings.VIDEO_DEFAULT_WEIGHTS[1])),
                float(w.get("temporal",  settings.VIDEO_DEFAULT_WEIGHTS[2])),
            ]
        elif isinstance(w, list) and len(w) == 3:
            weights = [float(x) for x in w]
        else:
            return None, 0.5
        t = sum(weights)
        weights = [x/t for x in weights]
        # config order: [spatial, frequency, temporal]
        # registry order: [spatial, temporal, freq_srm]
        return [weights[0], weights[2], weights[1]], float(cfg.get("threshold", 0.5))
    except Exception as e:
        logger.warning(f"Video config failed: {e}")
        return None, 0.5


def build_image_ensemble(device: str) -> EnsembleState:
    models_map = {
        "efficientnet": (DeepfakeEfficientNetB4, settings.IMAGE_EFFICIENTNET_PATH, True),
        "vit":          (DeepfakeViT,            settings.IMAGE_VIT_PATH,          False),
        "freqcnn":      (DeepfakeFreqCNN,        settings.IMAGE_FREQCNN_PATH,      True),
    }
    loaded, statuses = [], {}
    for name, (Cls, path, is_freq) in models_map.items():
        try:
            model = Cls().to(device)
            ok, err = _load_checkpoint(path, model, device, is_freqcnn=is_freq)
            statuses[name] = ModelLoadStatus(loaded=ok, path=path, error=err)
            loaded.append(model if ok else None)
            if not ok: logger.warning(f"Image '{name}': {err}")
        except Exception as e:
            statuses[name] = ModelLoadStatus(loaded=False, path=path, error=str(e))
            loaded.append(None)

    weights, threshold = _load_image_config(settings.IMAGE_ENSEMBLE_CONFIG)
    if weights is None:
        weights, source = list(settings.IMAGE_DEFAULT_WEIGHTS), "default"
    else:
        source = "config_file"

    return EnsembleState(
        model_1=loaded[0], model_2=loaded[1], model_3=loaded[2],
        weights=weights, weight_source=source, statuses=statuses,
        device=device, decision_threshold=threshold,
    )


def build_video_ensemble(device: str) -> EnsembleState:
    models_map = {
        "spatial":  (SpatialCNN,         settings.VIDEO_SPATIAL_PATH,  False),
        "temporal": (TemporalTransformer, settings.VIDEO_TEMPORAL_PATH, False),
        "freq_srm": (FrequencySRMCNN,     settings.VIDEO_FREQ_SRM_PATH, False),
    }
    loaded, statuses = [], {}
    for name, (Cls, path, is_freq) in models_map.items():
        try:
            model = Cls().to(device)
            ok, err = _load_checkpoint(path, model, device, is_freqcnn=is_freq)
            statuses[name] = ModelLoadStatus(loaded=ok, path=path, error=err)
            loaded.append(model if ok else None)
            if not ok: logger.warning(f"Video '{name}': {err}")
        except Exception as e:
            statuses[name] = ModelLoadStatus(loaded=False, path=path, error=str(e))
            loaded.append(None)

    weights, threshold = _load_video_config(settings.VIDEO_ENSEMBLE_CONFIG)
    if weights is None:
        weights, source = list(settings.VIDEO_DEFAULT_WEIGHTS), "default"
    else:
        source = "config_file"

    return EnsembleState(
        model_1=loaded[0], model_2=loaded[1], model_3=loaded[2],
        weights=weights, weight_source=source, statuses=statuses,
        device=device, decision_threshold=threshold,
    )


_registry: dict = {}


def load_all_models() -> dict:
    global _registry
    device = _resolve_device()
    logger.info(f"Loading on device: {device}")
    _registry["image"] = build_image_ensemble(device)
    _registry["video"] = build_video_ensemble(device)
    img_ok = sum(1 for m in [_registry["image"].model_1,
                               _registry["image"].model_2,
                               _registry["image"].model_3] if m)
    vid_ok = sum(1 for m in [_registry["video"].model_1,
                               _registry["video"].model_2,
                               _registry["video"].model_3] if m)
    logger.info(f"Image: {img_ok}/3 | Video: {vid_ok}/3")
    return _registry


def get_image_ensemble() -> EnsembleState:
    return _registry.get("image")


def get_video_ensemble() -> EnsembleState:
    return _registry.get("video")


# ══════════════════════════════════════════════════════════════════
# 5-RULE ENSEMBLE
# ══════════════════════════════════════════════════════════════════

_SHARPEN_T = 1.35


def sharpen_confidence(p: float, T: float = _SHARPEN_T) -> float:
    eps = 1e-7
    p = max(eps, min(1.0-eps, p))
    return float(1.0 / (1.0 + math.exp(-math.log(p/(1.0-p)) * T)))


def confidence_pct(p_fake: float) -> float:
    """
    Confidence is ALWAYS >= the dominant-side probability.

    If ensemble=83% FAKE  → conviction=83% → confidence >= 83%  (returns ~87%)
    If ensemble=67% FAKE  → conviction=67% → confidence >= 67%  (returns ~75%)
    If ensemble= 8% FAKE  → conviction=92% → confidence >= 92%  (returns ~94%)
    If ensemble=45% FAKE  → conviction=55% → confidence >= 55%  (returns ~63%)

    Formula: conf = conviction + (1 - conviction) * 0.25
    Hard floor: conf >= conviction  (guaranteed by math, enforced explicitly)
    """
    eps = 1e-7
    p = max(eps, min(1.0 - eps, float(p_fake)))
    conviction = max(p, 1.0 - p)                   # 0.5 → 1.0
    conf = conviction + (1.0 - conviction) * 0.25   # always > conviction
    conf = max(conf, conviction + 0.005)             # hard floor
    return round(min(conf, 1.0) * 100, 1)



def _wavg(scores, weights):
    t = sum(weights)
    return sum(s*w for s, w in zip(scores, weights)) / t if t > 0 else 0.5


def _reweight(scores, base_w, dom_idx, share):
    n = len(scores)
    per_dom = share / len(dom_idx)
    other = [i for i in range(n) if i not in dom_idx]
    other_sum = sum(base_w[i] for i in other) or 1e-9
    nw = [0.0] * n
    for i in dom_idx:
        nw[i] = per_dom
    for i in other:
        nw[i] = (1.0-share) * (base_w[i]/other_sum)
    t = sum(nw) or 1e-9
    return _wavg(scores, [w/t for w in nw])


def five_rule_ensemble(p1, p2, p3, w1, w2, w3):
    probs  = [p1, p2, p3]
    base_w = [w1, w2, w3]
    raw    = _wavg(probs, base_w)

    dom1 = [i for i, p in enumerate(probs) if p >= 0.90]
    if dom1:
        return float(max(_reweight(probs, base_w, dom1, 0.70), raw)), "Rule1(≥90%)"

    if any(p < 0.10 for p in probs):
        return float(min(probs) * 0.75), "Rule2(<10%)"

    dom3 = [i for i, p in enumerate(probs) if p >= 0.80]
    if dom3:
        return float(_reweight(probs, base_w, dom3, 0.65)), "Rule3(≥80%)"

    dom4 = [i for i, p in enumerate(probs) if p <= 0.20]
    if dom4:
        return float(_reweight(probs, base_w, dom4, 0.65)), "Rule4(≤20%)"

    return float(raw), "Rule5(avg)"


@torch.no_grad()
def run_single_model(model, tensor):
    model.eval()
    out = model(tensor)
    if out.dim() > 1:
        out = out.squeeze(1)
    return float(torch.sigmoid(out).mean().item())


def compute_ensemble_probability(ensemble, tensors, apply_sharpening=True):
    per_model = {}
    for i, (model, _) in enumerate(zip(
        [ensemble.model_1, ensemble.model_2, ensemble.model_3],
        ensemble.weights,
    )):
        key = f"model_{i+1}"
        if model is None:
            per_model[key] = 0.5
            continue
        try:
            if i == 1 and "sequence" in tensors:
                t = tensors["sequence"].to(ensemble.device)
            elif i == 2 and "fft" in tensors:
                t = tensors["fft"].to(ensemble.device)
            else:
                t = tensors["standard"].to(ensemble.device)
            per_model[key] = run_single_model(model, t)
        except Exception as e:
            logger.warning(f"Model {i+1} failed: {e}")
            per_model[key] = 0.5

    p1 = per_model.get("model_1", 0.5)
    p2 = per_model.get("model_2", 0.5)
    p3 = per_model.get("model_3", 0.5)
    w1, w2, w3 = ensemble.weights

    p_raw, rule = five_rule_ensemble(p1, p2, p3, w1, w2, w3)
    p_final = sharpen_confidence(p_raw) if apply_sharpening else p_raw
    conf = confidence_pct(p_final)

    return float(p_final), per_model, rule, conf


def compute_model_agreement(per_model):
    scores = list(per_model.values())
    spread = max(scores) - min(scores)
    if spread <= 0.15: return "high"
    if spread <= 0.25: return "medium"
    return "low"


def dominant_model_boost(p1, p2, p3, w1, w2, w3):
    return w1, w2, w3
