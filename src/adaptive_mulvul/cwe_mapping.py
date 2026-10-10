"""Generate an auditable coarse CWE map from the official MITRE catalog."""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter, deque
from dataclasses import asdict, dataclass
from pathlib import Path

from .primevul import iter_primevul


CATEGORY_DEFINITIONS = {
    "memory": "Unsafe memory access, bounds, pointer lifetime, or memory initialization.",
    "injection": "Untrusted data changes commands, code, queries, paths, formats, or interpreted structure.",
    "input": "External input is missing validation, normalization, or representation checks without instruction execution.",
    "numeric": "Integer, floating-point, conversion, calculation, or divide-by-zero errors.",
    "resource": "Incorrect allocation, release, lifetime, exhaustion, or availability of resources.",
    "concurrency": "Race conditions, locking, ordering, synchronization, or shared-state errors.",
    "access": "Authentication, authorization, permission, privilege, trust, or identity failures.",
    "crypto": "Incorrect cryptography, randomness, certificates, keys, hashing, or secure transport.",
    "information": "Unintended disclosure, exposure, logging, storage, or observable information leakage.",
    "logic": "Security-relevant control-flow, state, API-use, exceptional-condition, or other logic errors.",
    "benign": "No supported vulnerability pattern is present in the code.",
}

# Representative CWE roots and legacy NVD category IDs. Descendants in the
# Research Concepts view inherit the corresponding class. Overlap is resolved
# by the priority order below and recorded in the generated evidence.
ROOTS = {
    "memory": {118, 119, 120, 125, 415, 416, 476, 562, 590, 761, 762, 763, 787, 824, 825, 843, 908},
    "injection": {22, 59, 74, 77, 78, 79, 88, 89, 90, 91, 93, 94, 99, 134, 434, 502, 610, 611, 643, 706, 707, 829, 917, 918, 943},
    "input": {20, 129, 1284, 1285, 1286, 1287, 1288, 1289},
    "numeric": {128, 189, 190, 191, 193, 369, 681, 682},
    "resource": {399, 400, 401, 404, 459, 664, 665, 666, 672, 674, 770, 772, 775, 834, 835},
    "concurrency": {361, 362, 364, 366, 367, 368, 662, 663, 667, 820, 821, 822, 823, 831, 832, 833},
    "access": {254, 255, 259, 264, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 281, 282, 283, 284, 285, 286, 287, 288, 290, 294, 295, 306, 307, 308, 309, 732, 862, 863},
    "crypto": {310, 311, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 522},
    "information": {200, 201, 203, 209, 212, 215, 226, 244, 312, 359, 497, 532, 534, 535, 536, 537, 538, 539, 540, 548, 552, 598, 922},
    "logic": {16, 17, 19, 252, 345, 354, 358, 388, 391, 392, 393, 394, 395, 396, 397, 417, 426, 427, 436, 453, 460, 484, 601, 617, 668, 703, 704, 754, 755, 756, 909, 1021},
}

PRIORITY = tuple(key for key in CATEGORY_DEFINITIONS if key != "benign")

# Cross-cutting weaknesses for which ancestry alone is semantically ambiguous.
# Keeping these decisions explicit makes the generated map reviewable instead
# of burying special cases in keyword order.
OVERRIDES = {
    172: "input",        # generic encoding error, not necessarily injection
    241: "input",        # unexpected input data type
    295: "crypto",       # certificate validation
    345: "access",       # authenticity verification
    346: "access",       # origin validation
    352: "access",       # forged authenticated request (CSRF)
    444: "injection",    # request-smuggling parser disagreement
    522: "access",       # credential protection
    601: "input",        # untrusted redirect target, no instruction execution
    613: "access",       # session expiration
    668: "access",       # resource exposed to the wrong trust sphere
    670: "logic",        # incorrect control flow
    697: "logic",        # incorrect comparison
    798: "access",       # hard-coded credentials
    909: "resource",     # missing resource initialization
    1021: "access",      # clickjacking / UI access boundary
}

KEYWORDS = {
    "memory": ("buffer", "memory", "pointer", "use after free", "out-of-bounds", "uninitialized"),
    "injection": ("injection", "neutralization", "command", "query", "path traversal", "deserialization"),
    "input": ("input validation", "validation", "canonicalization", "encoding", "representation"),
    "numeric": ("integer", "numeric", "calculation", "divide", "conversion", "precision"),
    "resource": ("resource", "allocation", "release", "exhaustion", "uncontrolled recursion", "infinite loop"),
    "concurrency": ("race condition", "concurrent", "synchronization", "lock", "time-of-check"),
    "access": ("authorization", "authentication", "permission", "privilege", "access control", "identity"),
    "crypto": ("cryptographic", "encryption", "random", "certificate", "key", "hash"),
    "information": ("information exposure", "sensitive information", "data leak", "observable discrepancy"),
    "logic": ("logic", "exception", "error condition", "state", "incorrect behavior", "api"),
}


@dataclass(frozen=True)
class CweEntry:
    cwe_id: int
    name: str
    description: str
    parents: tuple[int, ...]


@dataclass(frozen=True)
class MappingDecision:
    cwe: str
    name: str
    category: str
    confidence: str
    method: str
    evidence: tuple[str, ...]
    dataset_count: int


def load_catalog(path: str | Path) -> tuple[str, dict[int, CweEntry]]:
    root = ET.parse(path).getroot()
    namespace = {"cwe": root.tag.split("}", 1)[0].removeprefix("{")}
    entries: dict[int, CweEntry] = {}
    for element_name in ("Weakness", "Category"):
        for element in root.findall(f".//cwe:{element_name}", namespace):
            cwe_id = int(element.attrib["ID"])
            description_node = element.find("cwe:Description", namespace)
            description = "" if description_node is None else " ".join(description_node.itertext())
            parents = {
                int(relation.attrib["CWE_ID"])
                for relation in element.findall(".//cwe:Related_Weakness", namespace)
                if relation.attrib.get("Nature") == "ChildOf"
                and relation.attrib.get("View_ID") == "1000"
            }
            entries[cwe_id] = CweEntry(
                cwe_id=cwe_id,
                name=element.attrib.get("Name", ""),
                description=" ".join(description.split()),
                parents=tuple(sorted(parents)),
            )
    return root.attrib.get("Version", "unknown"), entries


def ancestor_distances(cwe_id: int, entries: dict[int, CweEntry]) -> dict[int, int]:
    distances = {cwe_id: 0}
    queue = deque([cwe_id])
    while queue:
        current = queue.popleft()
        entry = entries.get(current)
        if entry is None:
            continue
        for parent in entry.parents:
            distance = distances[current] + 1
            if parent not in distances or distance < distances[parent]:
                distances[parent] = distance
                queue.append(parent)
    return distances


def classify(cwe_id: int, entries: dict[int, CweEntry], dataset_count: int) -> MappingDecision:
    entry = entries.get(cwe_id, CweEntry(cwe_id, "Unknown CWE", "", ()))
    if cwe_id in OVERRIDES:
        return MappingDecision(
            cwe=f"CWE-{cwe_id}", name=entry.name, category=OVERRIDES[cwe_id],
            confidence="high", method="explicit-override",
            evidence=("cross-cutting-CWE-reviewed",), dataset_count=dataset_count,
        )
    distances = ancestor_distances(cwe_id, entries)
    candidates: list[tuple[int, int, str, int]] = []
    for priority, category in enumerate(PRIORITY):
        for root_id in ROOTS[category]:
            if root_id in distances:
                candidates.append((distances[root_id], priority, category, root_id))
    if candidates:
        distance, _, category, root_id = min(candidates)
        return MappingDecision(
            cwe=f"CWE-{cwe_id}",
            name=entry.name,
            category=category,
            confidence="high" if distance <= 1 else "medium",
            method="exact-root" if distance == 0 else "ancestor",
            evidence=(f"CWE-{root_id}", f"ancestor-distance={distance}"),
            dataset_count=dataset_count,
        )

    text = f"{entry.name} {entry.description}".lower()
    scores = Counter(
        {
            category: sum(bool(re.search(rf"\b{re.escape(term)}\b", text)) for term in terms)
            for category, terms in KEYWORDS.items()
        }
    )
    category, score = scores.most_common(1)[0]
    if score:
        terms = tuple(term for term in KEYWORDS[category] if term in text)
        return MappingDecision(
            cwe=f"CWE-{cwe_id}", name=entry.name, category=category,
            confidence="medium", method="keyword", evidence=terms,
            dataset_count=dataset_count,
        )
    return MappingDecision(
        cwe=f"CWE-{cwe_id}", name=entry.name, category="logic",
        confidence="low", method="fallback", evidence=("manual-review-required",),
        dataset_count=dataset_count,
    )


def dataset_cwe_counts(paths: list[Path]) -> Counter[int]:
    counts: Counter[int] = Counter()
    for path in paths:
        for sample in iter_primevul(path):
            if sample.target == 1:
                for cwe in sample.cwes:
                    match = re.fullmatch(r"CWE-(\d+)", cwe)
                    if match:
                        counts[int(match.group(1))] += 1
    return counts


def generate_mapping(catalog: Path, datasets: list[Path]) -> dict[str, object]:
    version, entries = load_catalog(catalog)
    counts = dataset_cwe_counts(datasets)
    decisions = [classify(cwe_id, entries, count) for cwe_id, count in sorted(counts.items())]
    return {
        "schema_version": 1,
        "source": "MITRE CWE XML",
        "cwe_version": version,
        "categories": CATEGORY_DEFINITIONS,
        "mapping": {decision.cwe: asdict(decision) for decision in decisions},
        "summary": {
            "cwe_count": len(decisions),
            "by_category": dict(sorted(Counter(d.category for d in decisions).items())),
            "by_confidence": dict(sorted(Counter(d.confidence for d in decisions).items())),
        },
    }


def load_mapping(path: str | Path) -> dict[str, str]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return {
        cwe: str(decision["category"])
        for cwe, decision in payload["mapping"].items()
    }


def coarse_labels(
    cwes: tuple[str, ...], target: int, mapping: dict[str, str]
) -> frozenset[str]:
    """Map a sample label; fixed samples remain benign despite paired CWE metadata."""
    if target == 0:
        return frozenset({"benign"})
    missing = sorted(set(cwes) - set(mapping))
    if missing:
        raise KeyError(f"CWE labels missing from coarse mapping: {missing}")
    labels = frozenset(mapping[cwe] for cwe in cwes)
    if not labels:
        raise ValueError("a vulnerable sample must have at least one mapped CWE")
    return labels


def _main() -> None:
    parser = argparse.ArgumentParser(description="Generate a coarse mapping for PrimeVul CWE labels")
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = generate_mapping(args.catalog, args.dataset)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    _main()
