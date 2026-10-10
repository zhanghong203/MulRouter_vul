import json

import pytest

from adaptive_mulvul.primevul import (
    audit_primevul,
    load_primevul,
    split_train_calibration,
    validate_paired,
)


def _row(idx, project, commit, target, cwe):
    return {
        "idx": idx,
        "project": project,
        "commit_id": commit,
        "target": target,
        "func": f"int f{idx}(void) {{ return {target}; }}",
        "func_hash": idx,
        "cwe": [cwe],
        "cve": f"CVE-{commit}",
        "file_name": "x.c",
    }


def test_load_audit_and_grouped_split(tmp_path):
    path = tmp_path / "primevul_train_paired.jsonl"
    rows = []
    for number in range(20):
        rows.extend(
            [
                _row(number * 2, "p", str(number), 1, "CWE-119"),
                _row(number * 2 + 1, "p", str(number), 0, "CWE-119"),
            ]
        )
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")

    samples = load_primevul(path)
    audit = audit_primevul(samples)
    train, calibration = split_train_calibration(samples, 0.25, seed=7)

    assert audit.rows == 40
    assert audit.pairs == 20
    assert audit.unique_cwes == 1
    assert {sample.group_id for sample in train}.isdisjoint(
        {sample.group_id for sample in calibration}
    )
    assert {sample.target for sample in train} == {0, 1}
    assert {sample.target for sample in calibration} == {0, 1}


def test_cross_commit_pair_is_preserved_in_one_partition(tmp_path):
    path = tmp_path / "bad.jsonl"
    rows = [
        _row(1, "p", "one", 1, "CWE-20"),
        _row(2, "p", "two", 0, "CWE-20"),
    ]
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    samples = load_primevul(path)
    validate_paired(samples)
    assert audit_primevul(samples).cross_commit_pairs == 1


def test_pair_validation_rejects_two_positive_rows(tmp_path):
    path = tmp_path / "bad-targets.jsonl"
    rows = [
        _row(1, "p", "one", 1, "CWE-20"),
        _row(2, "p", "one", 1, "CWE-20"),
    ]
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    with pytest.raises(ValueError, match="one vulnerable and one benign"):
        validate_paired(load_primevul(path))
