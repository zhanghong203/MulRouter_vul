"""Interfaces that isolate adaptive routing from a concrete LLM provider."""

from __future__ import annotations

from typing import Protocol, Sequence

from .schemas import DetectorFeedback, RouterPrediction


class Router(Protocol):
    def predict(self, code: str, evidence: Sequence[str]) -> RouterPrediction:
        """Score all coarse vulnerability categories."""


class Detector(Protocol):
    def detect(self, code: str, category: str, evidence: Sequence[str]) -> DetectorFeedback:
        """Inspect one coarse category and return structured evidence."""


class EvidenceRetriever(Protocol):
    def global_evidence(self, code: str) -> Sequence[str]:
        """Retrieve broad evidence for routing."""

    def category_evidence(self, code: str, category: str) -> Sequence[str]:
        """Retrieve contrastive evidence for one detector."""


class CodeTransformer(Protocol):
    def transform(self, code: str, language: str = "c") -> str:
        """Convert source code into a structured semantic representation."""

