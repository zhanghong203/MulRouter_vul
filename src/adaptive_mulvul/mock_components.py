"""Deterministic components for local demos and tests without API access."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .schemas import DetectorFeedback, RouterPrediction


class StaticRouter:
    def __init__(self, scores: Mapping[str, float]) -> None:
        self.scores = dict(scores)

    def predict(self, code: str, evidence: Sequence[str]) -> RouterPrediction:
        return RouterPrediction(self.scores)


class StaticDetector:
    def __init__(self, feedback_by_category: Mapping[str, DetectorFeedback]) -> None:
        self.feedback_by_category = dict(feedback_by_category)

    def detect(self, code: str, category: str, evidence: Sequence[str]) -> DetectorFeedback:
        return self.feedback_by_category[category]


class EmptyRetriever:
    def global_evidence(self, code: str) -> Sequence[str]:
        return ()

    def category_evidence(self, code: str, category: str) -> Sequence[str]:
        return ()

