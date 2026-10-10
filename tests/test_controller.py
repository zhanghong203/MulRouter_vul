from adaptive_mulvul.calibration import (
    CalibrationExample,
    ClassConditionalConformalCalibrator,
)
from adaptive_mulvul.controller import AdaptiveRoutingController
from adaptive_mulvul.mock_components import EmptyRetriever, StaticDetector, StaticRouter
from adaptive_mulvul.schemas import DetectorDecision, DetectorFeedback


def _feedback(category, decision, *, cwes=(), alternative=None, confidence=0.8):
    return DetectorFeedback(
        category=category,
        decision=decision,
        confidence=confidence,
        evidence_support=0.8,
        retrieval_quality=0.8,
        predicted_cwes=tuple(cwes),
        alternative_category=alternative,
    )


def test_detector_feedback_can_reroute_once():
    calibrator = ClassConditionalConformalCalibrator(
        alpha=0.2, min_examples_per_class=1
    ).fit(
        [
            CalibrationExample(
                {"memory": 0.6, "input": 0.4, "logic": 0.0},
                frozenset({"memory"}),
            ),
            CalibrationExample(
                {"memory": 0.4, "input": 0.6, "logic": 0.0},
                frozenset({"input"}),
            ),
        ]
    )
    controller = AdaptiveRoutingController(
        router=StaticRouter({"memory": 0.6, "input": 0.3, "logic": 0.1}),
        detector=StaticDetector(
            {
                "memory": _feedback(
                    "memory", DetectorDecision.NEGATIVE, alternative="input"
                ),
                "input": _feedback(
                    "input", DetectorDecision.POSITIVE, cwes=("CWE-20",)
                ),
                "logic": _feedback("logic", DetectorDecision.NEGATIVE),
            }
        ),
        retriever=EmptyRetriever(),
        calibrator=calibrator,
    )

    result = controller.analyze("void f(char *s) { use(s); }")

    assert result.rerouted is True
    assert [step.category for step in result.steps] == ["memory", "input"]
    assert result.predicted_cwes == ("CWE-20",)

