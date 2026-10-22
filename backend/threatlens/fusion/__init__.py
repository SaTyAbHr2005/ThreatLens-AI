"""M5 Risk Fusion & Explainability: signals → risk, drift, and explained alerts."""

from .drift import DriftTracker
from .explain import ContentCache, build_alert, counterfactual, factors, frameworks, recommendations
from .model import TIER_THRESHOLDS, Fused, Weights, fit_logistic, fuse, tier_for_risk
from .narrative import write_narrative
from .scorer import ALERT_THRESHOLD, FusionScorer
from .sinks import attach_minute_sink
from .store import MemoryAlertStore, MongoAlertStore

__all__ = [
    "ALERT_THRESHOLD",
    "TIER_THRESHOLDS",
    "ContentCache",
    "DriftTracker",
    "Fused",
    "FusionScorer",
    "MemoryAlertStore",
    "MongoAlertStore",
    "Weights",
    "attach_minute_sink",
    "build_alert",
    "counterfactual",
    "factors",
    "fit_logistic",
    "frameworks",
    "fuse",
    "recommendations",
    "tier_for_risk",
    "write_narrative",
]
