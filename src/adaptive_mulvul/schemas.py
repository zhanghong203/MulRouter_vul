"""Typed messages passed between the router, detectors, and controller."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from math import isfinite
from typing import Mapping


class DetectorDecision(str, Enum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    ABSTAIN = "abstain"


def _unit_interval(name: str, value: float) -> None:
    if not isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be a finite value in [0, 1]")


@dataclass(frozen=True)
class RouterPrediction:
    scores: Mapping[str, float]
    evidence_quality: float = 1.0

    def __post_init__(self) -> None:
        if not self.scores:
            raise ValueError("router scores cannot be empty")
        for category, score in self.scores.items():
            if not category.strip():
                raise ValueError("category names cannot be blank")
            if not isfinite(score) or score < 0.0:
                raise ValueError(f"invalid score for {category!r}: {score}")
        if sum(self.scores.values()) <= 0.0:
            raise ValueError("at least one router score must be positive")
        _unit_interval("evidence_quality", self.evidence_quality)

    def normalized_scores(self) -> dict[str, float]:
        total = sum(self.scores.values())
        return {category: score / total for category, score in self.scores.items()}


@dataclass(frozen=True)
class VulnerabilityCondition:
    source_found: bool = False
    sink_found: bool = False
    trigger_path_found: bool = False
    defense_found: bool = False


@dataclass(frozen=True)
class DetectorFeedback:
    category: str
    decision: DetectorDecision
    confidence: float
    evidence_support: float
    retrieval_quality: float
    predicted_cwes: tuple[str, ...] = ()
    conditions: VulnerabilityCondition = field(default_factory=VulnerabilityCondition)
    alternative_category: str | None = None
    reason_code: str = "UNSPECIFIED"

    def __post_init__(self) -> None:
        _unit_interval("confidence", self.confidence)
        _unit_interval("evidence_support", self.evidence_support)
        _unit_interval("retrieval_quality", self.retrieval_quality)
        if self.decision is DetectorDecision.POSITIVE and not self.predicted_cwes:
            raise ValueError("positive detector feedback must include a CWE")
        if self.alternative_category == self.category:
            raise ValueError("alternative_category must differ from category")


@dataclass(frozen=True)
class RoutingStep:
    category: str
    initial_rank: int | None
    feedback: DetectorFeedback
    inserted_by_feedback: bool = False


@dataclass(frozen=True)
class DetectionResult:
    predicted_cwes: tuple[str, ...]
    initial_candidates: tuple[str, ...]
    steps: tuple[RoutingStep, ...]
    rerouted: bool
    router_entropy: float
    router_margin: float

