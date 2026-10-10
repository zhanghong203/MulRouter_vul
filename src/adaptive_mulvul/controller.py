"""Sequential dynamic routing with at most one evidence-guided reroute."""

from __future__ import annotations

from dataclasses import dataclass

from .calibration import ClassConditionalConformalCalibrator
from .interfaces import CodeTransformer, Detector, EvidenceRetriever, Router
from .schemas import DetectionResult, DetectorDecision, RoutingStep
from .uncertainty import normalized_entropy, top_two_margin


@dataclass(frozen=True)
class RoutingConfig:
    min_candidates: int = 1
    max_candidates: int = 4
    positive_confidence: float = 0.75
    positive_evidence_support: float = 0.65
    allow_one_reroute: bool = True
    stop_on_stable_positive: bool = False
    benign_category: str = "benign"


class AdaptiveRoutingController:
    def __init__(
        self,
        router: Router,
        detector: Detector,
        retriever: EvidenceRetriever,
        calibrator: ClassConditionalConformalCalibrator,
        config: RoutingConfig | None = None,
        transformer: CodeTransformer | None = None,
    ) -> None:
        self.router = router
        self.detector = detector
        self.retriever = retriever
        self.calibrator = calibrator
        self.config = config or RoutingConfig()
        self.transformer = transformer

    def analyze(self, code: str) -> DetectionResult:
        analysis_code = self.transformer.transform(code) if self.transformer else code
        router_evidence = self.retriever.global_evidence(analysis_code)
        router_prediction = self.router.predict(analysis_code, router_evidence)
        probabilities = router_prediction.normalized_scores()
        candidates = self.calibrator.candidate_set(
            probabilities,
            min_candidates=self.config.min_candidates,
            max_candidates=self.config.max_candidates,
        )

        initial_rank = {category: rank for rank, category in enumerate(candidates, start=1)}
        queue = list(candidates)
        visited: set[str] = set()
        steps: list[RoutingStep] = []
        cwes: set[str] = set()
        rerouted = False

        while queue:
            category = queue.pop(0)
            if category in visited:
                continue
            visited.add(category)
            if category == self.config.benign_category:
                continue
            evidence = self.retriever.category_evidence(analysis_code, category)
            feedback = self.detector.detect(analysis_code, category, evidence)
            steps.append(
                RoutingStep(
                    category=category,
                    initial_rank=initial_rank.get(category),
                    feedback=feedback,
                    inserted_by_feedback=category not in initial_rank,
                )
            )

            if feedback.decision is DetectorDecision.POSITIVE:
                cwes.update(feedback.predicted_cwes)

            alternative = feedback.alternative_category
            if (
                self.config.allow_one_reroute
                and not rerouted
                and alternative
                and alternative not in visited
            ):
                queue = [item for item in queue if item != alternative]
                queue.insert(0, alternative)
                rerouted = True

            if self.config.stop_on_stable_positive and self._stable_positive(feedback):
                break

        return DetectionResult(
            predicted_cwes=tuple(sorted(cwes)),
            initial_candidates=candidates,
            steps=tuple(steps),
            rerouted=rerouted,
            router_entropy=normalized_entropy(probabilities),
            router_margin=top_two_margin(probabilities),
        )

    def _stable_positive(self, feedback) -> bool:
        return (
            feedback.decision is DetectorDecision.POSITIVE
            and feedback.confidence >= self.config.positive_confidence
            and feedback.evidence_support >= self.config.positive_evidence_support
        )

