from adaptive_mulvul.cwe_mapping import CweEntry, classify, coarse_labels


def test_exact_and_ancestor_mapping():
    entries = {
        119: CweEntry(119, "Memory buffer bounds", "", ()),
        125: CweEntry(125, "Out-of-bounds Read", "", (119,)),
        89: CweEntry(89, "SQL Injection", "", (74,)),
        74: CweEntry(74, "Injection", "", ()),
    }
    assert classify(125, entries, 2).category == "memory"
    assert classify(89, entries, 3).category == "injection"


def test_unknown_mapping_is_explicitly_low_confidence():
    decision = classify(99999, {}, 1)
    assert decision.category == "logic"
    assert decision.confidence == "low"
    assert decision.method == "fallback"


def test_fixed_member_of_pair_is_benign_despite_cwe_metadata():
    mapping = {"CWE-119": "memory"}
    assert coarse_labels(("CWE-119",), 0, mapping) == frozenset({"benign"})
    assert coarse_labels(("CWE-119",), 1, mapping) == frozenset({"memory"})
