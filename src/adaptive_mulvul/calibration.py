"""Class-conditional conformal calibration for dynamic detector sets."""

from __future__ import annotations

from dataclasses import dataclass, field
from math import ceil
from typing import Iterable, Mapping


@dataclass(frozen=True)
class CalibrationExample:
    probabilities: Mapping[str, float]
    true_categories: frozenset[str]


def _conformal_quantile(values: list[float], alpha: float) -> float:
    if not values:
        raise ValueError("cannot calculate a quantile from no values")
    ordered = sorted(values)
    rank = ceil((len(ordered) + 1) * (1.0 - alpha))
    return ordered[min(max(rank, 1), len(ordered)) - 1]


@dataclass
class ClassConditionalConformalCalibrator:
    alpha: float = 0.1
    min_examples_per_class: int = 5
    thresholds: dict[str, float] = field(default_factory=dict, init=False)
    global_threshold: float | None = field(default=None, init=False)

    def fit(self, examples: Iterable[CalibrationExample]) -> "ClassConditionalConformalCalibrator":
        if not 0.0 < self.alpha < 1.0:
            raise ValueError("alpha must be in (0, 1)")
        examples = list(examples)
        if not examples:
            raise ValueError("at least one calibration example is required")

        global_nonconformity: list[float] = []
        by_category: dict[str, list[float]] = {}
        for example in examples:
            for category in example.true_categories:
                if category not in example.probabilities:
                    raise ValueError(f"missing score for true category {category!r}")
                score = 1.0 - example.probabilities[category]
                global_nonconformity.append(score)
                by_category.setdefault(category, []).append(score)

        if not global_nonconformity:
            raise ValueError("calibration examples contain no positive categories")
        self.global_threshold = _conformal_quantile(global_nonconformity, self.alpha)
        self.thresholds = {
            category: _conformal_quantile(values, self.alpha)
            for category, values in by_category.items()
            if len(values) >= self.min_examples_per_class
        }
        return self

    def candidate_set(
        self,
        probabilities: Mapping[str, float],
        *,
        min_candidates: int = 1,
        max_candidates: int | None = None,
    ) -> tuple[str, ...]:
        if self.global_threshold is None:
            raise RuntimeError("calibrator must be fitted before prediction")
        ordered = sorted(probabilities, key=probabilities.__getitem__, reverse=True)
        selected = [
            category
            for category in ordered
            if 1.0 - probabilities[category]
            <= self.thresholds.get(category, self.global_threshold)
        ]
        for category in ordered:
            if len(selected) >= min_candidates:
                break
            if category not in selected:
                selected.append(category)
        selected.sort(key=probabilities.__getitem__, reverse=True)
        if max_candidates is not None:
            selected = selected[:max_candidates]
        return tuple(selected)

