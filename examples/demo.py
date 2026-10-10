"""Run the adaptive controller without API access."""

from adaptive_mulvul.calibration import (
    CalibrationExample,
    ClassConditionalConformalCalibrator,
)
from adaptive_mulvul.controller import AdaptiveRoutingController
from adaptive_mulvul.mock_components import EmptyRetriever, StaticDetector, StaticRouter
from adaptive_mulvul.schemas import DetectorDecision, DetectorFeedback


calibrator = ClassConditionalConformalCalibrator(
    alpha=0.2, min_examples_per_class=1
).fit(
    [
        CalibrationExample(
            {"memory": 0.65, "input": 0.25, "logic": 0.10},
            frozenset({"memory"}),
        ),
        CalibrationExample(
            {"memory": 0.25, "input": 0.65, "logic": 0.10},
            frozenset({"input"}),
        ),
    ]
)

controller = AdaptiveRoutingController(
    router=StaticRouter({"memory": 0.60, "input": 0.30, "logic": 0.10}),
    detector=StaticDetector(
        {
            "memory": DetectorFeedback(
                category="memory",
                decision=DetectorDecision.NEGATIVE,
                confidence=0.83,
                evidence_support=0.79,
                retrieval_quality=0.75,
                alternative_category="input",
                reason_code="BOUNDS_CHECK_PRESENT",
            ),
            "input": DetectorFeedback(
                category="input",
                decision=DetectorDecision.POSITIVE,
                confidence=0.88,
                evidence_support=0.84,
                retrieval_quality=0.80,
                predicted_cwes=("CWE-20",),
                reason_code="UNVALIDATED_EXTERNAL_INPUT",
            ),
            "logic": DetectorFeedback(
                category="logic",
                decision=DetectorDecision.NEGATIVE,
                confidence=0.70,
                evidence_support=0.65,
                retrieval_quality=0.68,
            ),
        }
    ),
    retriever=EmptyRetriever(),
    calibrator=calibrator,
)

result = controller.analyze("void handle(char *input) { use(input); }")
print("Initial candidates:", result.initial_candidates)
print("Visited detectors:", tuple(step.category for step in result.steps))
print("Rerouted:", result.rerouted)
print("Predicted CWEs:", result.predicted_cwes)
