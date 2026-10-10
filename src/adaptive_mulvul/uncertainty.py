"""Uncertainty summaries for normalized router category scores."""

from __future__ import annotations

from math import log
from typing import Mapping


def normalized_entropy(probabilities: Mapping[str, float]) -> float:
    values = [value for value in probabilities.values() if value > 0.0]
    if len(probabilities) <= 1:
        return 0.0
    return -sum(value * log(value) for value in values) / log(len(probabilities))


def top_two_margin(probabilities: Mapping[str, float]) -> float:
    ordered = sorted(probabilities.values(), reverse=True)
    if len(ordered) == 1:
        return ordered[0]
    return ordered[0] - ordered[1]

