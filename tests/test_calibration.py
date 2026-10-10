from adaptive_mulvul.calibration import (
    CalibrationExample,
    ClassConditionalConformalCalibrator,
)


def test_candidate_set_changes_with_router_uncertainty():
    examples = [
        CalibrationExample({"memory": 0.5, "input": 0.5}, frozenset({"memory"})),
        CalibrationExample({"memory": 0.4, "input": 0.6}, frozenset({"memory"})),
        CalibrationExample({"memory": 0.5, "input": 0.5}, frozenset({"input"})),
        CalibrationExample({"memory": 0.6, "input": 0.4}, frozenset({"input"})),
    ]
    calibrator = ClassConditionalConformalCalibrator(
        alpha=0.2, min_examples_per_class=2
    ).fit(examples)

    assert calibrator.candidate_set({"memory": 0.9, "input": 0.1}) == ("memory",)
    assert calibrator.candidate_set({"memory": 0.55, "input": 0.45}) == (
        "memory",
        "input",
    )

