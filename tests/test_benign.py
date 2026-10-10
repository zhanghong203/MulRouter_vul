from adaptive_mulvul.calibration import (
    CalibrationExample,
    ClassConditionalConformalCalibrator,
)
from adaptive_mulvul.controller import AdaptiveRoutingController
from adaptive_mulvul.mock_components import EmptyRetriever, StaticDetector, StaticRouter


def test_benign_candidate_does_not_call_a_detector():
    calibrator = ClassConditionalConformalCalibrator(
        alpha=0.2, min_examples_per_class=1
    ).fit(
        [
            CalibrationExample(
                {"benign": 0.9, "memory": 0.1}, frozenset({"benign"})
            )
        ]
    )
    controller = AdaptiveRoutingController(
        router=StaticRouter({"benign": 0.95, "memory": 0.05}),
        detector=StaticDetector({}),
        retriever=EmptyRetriever(),
        calibrator=calibrator,
    )

    result = controller.analyze("int square(int x) { return x * x; }")

    assert result.initial_candidates == ("benign",)
    assert result.steps == ()
    assert result.predicted_cwes == ()
