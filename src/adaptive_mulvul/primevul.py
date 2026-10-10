"""PrimeVul paired-JSONL loading and leakage-safe splitting utilities."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class PrimeVulSample:
    idx: int
    project: str
    commit_id: str
    target: int
    function: str
    function_hash: str
    cwes: tuple[str, ...]
    cve: str | None = None
    file_name: str | None = None

    @property
    def group_id(self) -> str:
        """Keep every function from one security fix in the same partition."""
        return f"{self.project}\0{self.commit_id}"


@dataclass(frozen=True)
class PrimeVulAudit:
    rows: int
    vulnerable: int
    benign: int
    pairs: int
    unique_cwes: int
    duplicate_function_hash_rows: int
    cross_commit_pairs: int


def iter_primevul(path: str | Path) -> Iterator[PrimeVulSample]:
    source = Path(path)
    with source.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                target = int(row["target"])
                if target not in (0, 1):
                    raise ValueError("target must be 0 or 1")
                function = str(row["func"])
                if not function.strip():
                    raise ValueError("func is empty")
                raw_cwes = row.get("cwe") or []
                if isinstance(raw_cwes, str):
                    raw_cwes = [raw_cwes]
                cwes = tuple(sorted({str(item).strip().upper() for item in raw_cwes if str(item).strip()}))
                yield PrimeVulSample(
                    idx=int(row["idx"]),
                    project=str(row["project"]),
                    commit_id=str(row["commit_id"]),
                    target=target,
                    function=function,
                    function_hash=str(row["func_hash"]),
                    cwes=cwes,
                    cve=str(row["cve"]) if row.get("cve") else None,
                    file_name=str(row["file_name"]) if row.get("file_name") else None,
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError(f"invalid PrimeVul row at {source}:{line_number}: {exc}") from exc


def load_primevul(path: str | Path) -> tuple[PrimeVulSample, ...]:
    return tuple(iter_primevul(path))


def validate_paired(samples: tuple[PrimeVulSample, ...]) -> None:
    if len(samples) % 2:
        raise ValueError("paired PrimeVul data must contain an even number of rows")
    for offset in range(0, len(samples), 2):
        first, second = samples[offset : offset + 2]
        if {first.target, second.target} != {0, 1}:
            raise ValueError(f"rows {offset + 1}-{offset + 2} lack one vulnerable and one benign sample")


def audit_primevul(samples: tuple[PrimeVulSample, ...]) -> PrimeVulAudit:
    validate_paired(samples)
    targets = Counter(sample.target for sample in samples)
    hashes = Counter(sample.function_hash for sample in samples)
    cwes = {cwe for sample in samples if sample.target == 1 for cwe in sample.cwes}
    return PrimeVulAudit(
        rows=len(samples),
        vulnerable=targets[1],
        benign=targets[0],
        pairs=len(samples) // 2,
        unique_cwes=len(cwes),
        duplicate_function_hash_rows=sum(count - 1 for count in hashes.values() if count > 1),
        cross_commit_pairs=sum(
            samples[offset].group_id != samples[offset + 1].group_id
            for offset in range(0, len(samples), 2)
        ),
    )


def split_train_calibration(
    samples: tuple[PrimeVulSample, ...],
    calibration_fraction: float = 0.2,
    seed: int = 42,
) -> tuple[tuple[PrimeVulSample, ...], tuple[PrimeVulSample, ...]]:
    """Split by project+commit so paired/related functions cannot cross partitions."""
    if not 0.0 < calibration_fraction < 1.0:
        raise ValueError("calibration_fraction must be between 0 and 1")
    validate_paired(samples)
    # Union the dataset-provided adjacent pairs and all samples sharing a
    # project+commit. Hashing these connected components preserves both kinds
    # of relationship, including the small number of cross-commit pairs in the
    # official paired files.
    parent = list(range(len(samples)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    first_by_group: dict[str, int] = {}
    for offset in range(0, len(samples), 2):
        union(offset, offset + 1)
    for index, sample in enumerate(samples):
        previous = first_by_group.setdefault(sample.group_id, index)
        union(previous, index)

    members: dict[int, list[int]] = {}
    for index in range(len(samples)):
        members.setdefault(find(index), []).append(index)

    train: list[PrimeVulSample] = []
    calibration: list[PrimeVulSample] = []
    boundary = int(calibration_fraction * (1 << 64))
    for indices in members.values():
        component_key = "\0".join(sorted({samples[index].group_id for index in indices}))
        digest = hashlib.blake2b(
            f"{seed}\0{component_key}".encode(), digest_size=8
        ).digest()
        destination = calibration if int.from_bytes(digest, "big") < boundary else train
        destination.extend(samples[index] for index in indices)
    if not train or not calibration:
        raise ValueError("split produced an empty partition; adjust fraction or seed")
    return tuple(train), tuple(calibration)


def _main() -> None:
    parser = argparse.ArgumentParser(description="Validate and summarize paired PrimeVul JSONL")
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--calibration-fraction", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    for path in args.paths:
        samples = load_primevul(path)
        audit = audit_primevul(samples)
        print(f"{path}: {audit}")
        if "train" in path.name:
            train, calibration = split_train_calibration(
                samples, args.calibration_fraction, args.seed
            )
            print(f"  leakage-safe split: train={len(train)}, calibration={len(calibration)}")


if __name__ == "__main__":
    _main()
