"""OpenAI-compatible Router and Detector implementations.

The adapters use Chat Completions JSON mode because many third-party,
OpenAI-compatible gateways support it. Responses are validated locally before
they enter the routing controller.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from openai import OpenAI

from .schemas import (
    DetectorDecision,
    DetectorFeedback,
    RouterPrediction,
    VulnerabilityCondition,
)
from .settings import LLMSettings


def _json_completion(
    client: OpenAI,
    *,
    model: str,
    developer_prompt: str,
    user_prompt: str,
) -> dict[str, Any]:
    completion = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "developer", "content": developer_prompt},
            {"role": "user", "content": user_prompt},
        ],
        response_format={"type": "json_object"},
        temperature=0,
    )
    content = completion.choices[0].message.content
    if not content:
        raise RuntimeError("model returned an empty response")
    parsed = json.loads(content)
    if not isinstance(parsed, dict):
        raise ValueError("model response must be a JSON object")
    return parsed


class OpenAICompatibleRouter:
    def __init__(
        self,
        client: OpenAI,
        model: str,
        category_definitions: Mapping[str, str],
    ) -> None:
        if not category_definitions:
            raise ValueError("at least one category definition is required")
        self.client = client
        self.model = model
        self.category_definitions = dict(category_definitions)

    @classmethod
    def from_settings(
        cls,
        settings: LLMSettings,
        category_definitions: Mapping[str, str],
    ) -> "OpenAICompatibleRouter":
        client = OpenAI(api_key=settings.api_key, base_url=settings.base_url)
        return cls(client, settings.router_model, category_definitions)

    def predict(self, code: str, evidence: Sequence[str]) -> RouterPrediction:
        categories = "\n".join(
            f"- {name}: {description}"
            for name, description in self.category_definitions.items()
        )
        payload = _json_completion(
            self.client,
            model=self.model,
            developer_prompt=(
                "You are the coarse-grained router in a code vulnerability "
                "detection system. Score every supplied category. Do not invent "
                "categories. Return JSON only. Scores must be probabilities in "
                "[0, 1] and must sum to 1. Safe code must place its probability "
                "on the supplied benign category rather than assigning zero to "
                "every category."
            ),
            user_prompt=(
                f"Categories:\n{categories}\n\n"
                f"Retrieved evidence:\n{list(evidence)}\n\n"
                f"Code:\n```\n{code}\n```\n\n"
                "Return exactly this shape: "
                '{"scores":{"category":0.0},"evidence_quality":0.0}'
            ),
        )
        raw_scores = payload.get("scores")
        if not isinstance(raw_scores, dict):
            raise ValueError("router response is missing the scores object")
        expected = set(self.category_definitions)
        received = set(raw_scores)
        if received != expected:
            raise ValueError(
                f"router categories mismatch; missing={expected-received}, "
                f"unexpected={received-expected}"
            )
        scores = {name: float(raw_scores[name]) for name in self.category_definitions}
        return RouterPrediction(
            scores=scores,
            evidence_quality=float(payload.get("evidence_quality", 0.0)),
        )


class OpenAICompatibleDetector:
    def __init__(
        self,
        client: OpenAI,
        model: str,
        category_definitions: Mapping[str, str],
    ) -> None:
        self.client = client
        self.model = model
        self.category_definitions = dict(category_definitions)

    @classmethod
    def from_settings(
        cls,
        settings: LLMSettings,
        category_definitions: Mapping[str, str],
    ) -> "OpenAICompatibleDetector":
        client = OpenAI(api_key=settings.api_key, base_url=settings.base_url)
        return cls(client, settings.detector_model, category_definitions)

    def detect(
        self,
        code: str,
        category: str,
        evidence: Sequence[str],
    ) -> DetectorFeedback:
        if category not in self.category_definitions:
            raise ValueError(f"unknown detector category: {category}")
        alternatives = [name for name in self.category_definitions if name != category]
        payload = _json_completion(
            self.client,
            model=self.model,
            developer_prompt=(
                "You are a category-specialized code vulnerability detector. "
                "Test concrete vulnerability preconditions and defensive checks. "
                "Do not claim a vulnerability without an executable trigger path. "
                "Return JSON only. If evidence points outside your assigned "
                "category, abstain or return negative and provide one alternative."
            ),
            user_prompt=(
                f"Assigned category: {category}\n"
                f"Definition: {self.category_definitions[category]}\n"
                f"Allowed alternative categories: {alternatives}\n\n"
                f"Contrastive evidence:\n{list(evidence)}\n\n"
                f"Code:\n```\n{code}\n```\n\n"
                "Return exactly these fields: decision (positive, negative, or "
                "abstain), confidence, evidence_support, retrieval_quality, "
                "predicted_cwes (array), conditions (source_found, sink_found, "
                "trigger_path_found, defense_found), alternative_category "
                "(string or null), and reason_code."
            ),
        )
        conditions = payload.get("conditions") or {}
        alternative = payload.get("alternative_category")
        if alternative is not None and alternative not in alternatives:
            raise ValueError(f"detector returned an invalid alternative: {alternative}")
        return DetectorFeedback(
            category=category,
            decision=DetectorDecision(str(payload["decision"]).lower()),
            confidence=float(payload["confidence"]),
            evidence_support=float(payload["evidence_support"]),
            retrieval_quality=float(payload["retrieval_quality"]),
            predicted_cwes=tuple(str(item) for item in payload.get("predicted_cwes", [])),
            conditions=VulnerabilityCondition(
                source_found=bool(conditions.get("source_found", False)),
                sink_found=bool(conditions.get("sink_found", False)),
                trigger_path_found=bool(conditions.get("trigger_path_found", False)),
                defense_found=bool(conditions.get("defense_found", False)),
            ),
            alternative_category=alternative,
            reason_code=str(payload.get("reason_code", "UNSPECIFIED")),
        )

