"""Resumable SCALE example store, UniXcoder embeddings, and FAISS retrieval."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from .cwe_mapping import coarse_labels, load_mapping
from .primevul import PrimeVulSample, load_primevul, split_train_calibration
from .scale_transformer import ScaleTransformer

CACHE_VERSION = "scale-v2-tolerant-c-cpp"


@dataclass(frozen=True)
class KnowledgeRecord:
    record_id: str
    sample_idx: int
    function_hash: str
    project: str
    commit_id: str
    target: int
    cwes: tuple[str, ...]
    categories: tuple[str, ...]
    scale_text: str

    def evidence_text(self) -> str:
        label = "benign" if self.target == 0 else ", ".join(self.cwes)
        return f"Label: {label}\nCategories: {', '.join(self.categories)}\n{self.scale_text}"


class BatchEmbedder(Protocol):
    model_name: str

    def encode(self, texts: Sequence[str], batch_size: int) -> "object":
        """Return an L2-normalized float32 numpy matrix."""


class UniXcoderEmbedder:
    """Official UniXcoder encoder-only pooling recipe, loaded lazily."""

    def __init__(
        self,
        model_name: str = "microsoft/unixcoder-base",
        device: str = "auto",
        max_length: int = 512,
    ) -> None:
        try:
            import torch
            from transformers import AutoModel, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError(
                "Install the retrieval dependencies from environment-server.yml"
            ) from exc
        self._torch = torch
        self.model_name = model_name
        self.max_length = max_length
        self.device = (
            "cuda" if device == "auto" and torch.cuda.is_available()
            else "cpu" if device == "auto" else device
        )
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name).to(self.device).eval()

    def _token_ids(self, text: str) -> list[int]:
        tokens = self.tokenizer.tokenize(text)[: self.max_length - 4]
        tokens = [
            self.tokenizer.cls_token,
            "<encoder-only>",
            self.tokenizer.sep_token,
            *tokens,
            self.tokenizer.sep_token,
        ]
        return self.tokenizer.convert_tokens_to_ids(tokens)

    def encode(self, texts: Sequence[str], batch_size: int = 16):
        import numpy as np

        vectors: list[object] = []
        torch = self._torch
        with torch.inference_mode():
            for start in range(0, len(texts), batch_size):
                rows = [self._token_ids(text) for text in texts[start : start + batch_size]]
                width = max(len(row) for row in rows)
                pad = self.tokenizer.pad_token_id
                ids = torch.tensor(
                    [row + [pad] * (width - len(row)) for row in rows],
                    device=self.device,
                )
                mask = ids.ne(pad)
                hidden = self.model(input_ids=ids, attention_mask=mask).last_hidden_state
                pooled = (hidden * mask.unsqueeze(-1)).sum(1) / mask.sum(1).unsqueeze(-1)
                pooled = torch.nn.functional.normalize(pooled, p=2, dim=1)
                vectors.append(pooled.cpu().numpy().astype("float32"))
        return np.concatenate(vectors, axis=0)


class ScaleCache:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS scale_cache (
            function_hash TEXT PRIMARY KEY,
            scale_text TEXT,
            error TEXT
            )"""
        )
        self.connection.commit()

    def get(self, function_hash: str) -> tuple[str | None, str | None] | None:
        row = self.connection.execute(
            "SELECT scale_text, error FROM scale_cache WHERE function_hash = ?",
            (function_hash,),
        ).fetchone()
        return None if row is None else (row[0], row[1])

    def put(self, function_hash: str, scale_text: str | None, error: str | None) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO scale_cache VALUES (?, ?, ?)",
            (function_hash, scale_text, error),
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "ScaleCache":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _record_id(sample: PrimeVulSample) -> str:
    return hashlib.sha256(
        f"{sample.idx}\0{sample.function_hash}".encode()
    ).hexdigest()[:24]


def prepare_scale_records(
    samples: Sequence[PrimeVulSample],
    mapping: dict[str, str],
    cache_path: str | Path,
    output_path: str | Path,
    transformer: ScaleTransformer | None = None,
) -> tuple[int, int]:
    """Transform samples once, cache each result, then atomically write JSONL."""
    transformer = transformer or ScaleTransformer()
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    completed = failed = 0
    with ScaleCache(cache_path) as cache, temporary.open("w", encoding="utf-8") as stream:
        for sample in samples:
            cache_key = f"{CACHE_VERSION}:{sample.function_hash}"
            cached = cache.get(cache_key)
            if cached is None:
                try:
                    cached = (transformer.transform(sample.function), None)
                except Exception as exc:  # preserve the failure and continue the batch
                    cached = (None, f"{type(exc).__name__}: {exc}")
                cache.put(cache_key, *cached)
            scale_text, error = cached
            if error or scale_text is None:
                failed += 1
                continue
            record = KnowledgeRecord(
                record_id=_record_id(sample), sample_idx=sample.idx,
                function_hash=sample.function_hash, project=sample.project,
                commit_id=sample.commit_id, target=sample.target,
                cwes=sample.cwes,
                categories=tuple(sorted(coarse_labels(sample.cwes, sample.target, mapping))),
                scale_text=scale_text,
            )
            stream.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")
            completed += 1
    os.replace(temporary, output)
    return completed, failed


def load_records(path: str | Path) -> list[KnowledgeRecord]:
    records: list[KnowledgeRecord] = []
    with Path(path).open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            row["cwes"] = tuple(row["cwes"])
            row["categories"] = tuple(row["categories"])
            records.append(KnowledgeRecord(**row))
    return records


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def embed_records_resumable(
    records_path: str | Path,
    output_dir: str | Path,
    embedder: BatchEmbedder,
    batch_size: int = 16,
) -> Path:
    import numpy as np

    records = load_records(records_path)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    vector_path = output / "embeddings.npy"
    state_path = output / "embedding_state.json"
    fingerprint = hashlib.sha256(
        "\n".join(record.record_id for record in records).encode()
    ).hexdigest()
    state = json.loads(state_path.read_text()) if state_path.exists() else None
    if state and (state["fingerprint"] != fingerprint or state["model"] != embedder.model_name):
        raise ValueError("existing embedding checkpoint belongs to different records or model")
    completed = int(state["completed"]) if state else 0
    matrix = None
    for start in range(completed, len(records), batch_size):
        batch = records[start : start + batch_size]
        vectors = embedder.encode([record.scale_text for record in batch], batch_size)
        vectors = np.asarray(vectors, dtype="float32")
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        vectors = vectors / np.maximum(norms, 1e-12)
        if matrix is None:
            if completed:
                matrix = np.lib.format.open_memmap(vector_path, mode="r+")
            else:
                matrix = np.lib.format.open_memmap(
                    vector_path, mode="w+", dtype="float32",
                    shape=(len(records), vectors.shape[1]),
                )
        matrix[start : start + len(batch)] = vectors
        matrix.flush()
        completed = start + len(batch)
        _atomic_json(state_path, {
            "fingerprint": fingerprint, "model": embedder.model_name,
            "completed": completed, "records": len(records),
            "dimension": int(vectors.shape[1]),
        })
    return vector_path


def build_faiss_indices(
    records_path: str | Path,
    embeddings_path: str | Path,
    output_dir: str | Path,
) -> dict[str, int]:
    try:
        import faiss
        import numpy as np
    except ImportError as exc:
        raise RuntimeError("FAISS and numpy are required; use environment-server.yml") from exc
    records = load_records(records_path)
    vectors = np.load(embeddings_path, mmap_mode="r")
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    partitions: dict[str, list[int]] = {
        "global": list(range(len(records))),
        "benign": [i for i, record in enumerate(records) if record.target == 0],
        "vulnerable": [i for i, record in enumerate(records) if record.target == 1],
    }
    categories = sorted({category for record in records for category in record.categories if category != "benign"})
    for category in categories:
        partitions[f"category_{category}"] = [
            i for i, record in enumerate(records)
            if record.target == 1 and category in record.categories
        ]
    sizes: dict[str, int] = {}
    for name, ids in partitions.items():
        if not ids:
            continue
        subset = np.asarray(vectors[ids], dtype="float32")
        index = faiss.IndexFlatIP(subset.shape[1])
        index.add(subset)
        faiss.write_index(index, str(output / f"{name}.faiss"))
        np.save(output / f"{name}.ids.npy", np.asarray(ids, dtype="int64"))
        sizes[name] = len(ids)
    _atomic_json(output / "manifest.json", {
        "metric": "cosine_via_normalized_inner_product",
        "records": len(records), "dimension": int(vectors.shape[1]),
        "partitions": sizes,
    })
    return sizes


class FaissEvidenceRetriever:
    """MulVul-style global and contrastive evidence retrieval."""

    def __init__(
        self,
        records_path: str | Path,
        index_dir: str | Path,
        embedder: BatchEmbedder,
        global_k: int = 5,
        per_pool_k: int = 3,
    ) -> None:
        try:
            import faiss
            import numpy as np
        except ImportError as exc:
            raise RuntimeError("FAISS and numpy are required; use environment-server.yml") from exc
        self._faiss, self._np = faiss, np
        self.records = load_records(records_path)
        self.index_dir = Path(index_dir)
        self.embedder = embedder
        self.global_k = global_k
        self.per_pool_k = per_pool_k
        self._indices: dict[str, tuple[object, object]] = {}

    def _search(self, pool: str, code: str, k: int) -> list[KnowledgeRecord]:
        if pool not in self._indices:
            index = self._faiss.read_index(str(self.index_dir / f"{pool}.faiss"))
            ids = self._np.load(self.index_dir / f"{pool}.ids.npy")
            self._indices[pool] = (index, ids)
        index, ids = self._indices[pool]
        query = self.embedder.encode([code], 1)
        query = self._np.asarray(query, dtype="float32")
        self._faiss.normalize_L2(query)
        _, neighbors = index.search(query, min(k, index.ntotal))
        return [self.records[int(ids[position])] for position in neighbors[0] if position >= 0]

    def global_evidence(self, code: str) -> Sequence[str]:
        return [record.evidence_text() for record in self._search("global", code, self.global_k)]

    def category_evidence(self, code: str, category: str) -> Sequence[str]:
        positives = self._search(f"category_{category}", code, self.per_pool_k)
        benign = self._search("benign", code, self.per_pool_k)
        candidates = self._search("vulnerable", code, self.per_pool_k * 5)
        hard = [record for record in candidates if category not in record.categories][: self.per_pool_k]
        sections = [
            *(f"[IN-CATEGORY POSITIVE]\n{record.evidence_text()}" for record in positives),
            *(f"[BENIGN COUNTEREXAMPLE]\n{record.evidence_text()}" for record in benign),
            *(f"[OUT-OF-CATEGORY HARD NEGATIVE]\n{record.evidence_text()}" for record in hard),
        ]
        return sections


def _main() -> None:
    parser = argparse.ArgumentParser(description="Build a resumable MulVul-style example knowledge base")
    parser.add_argument("--train", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("artifacts/knowledge_base"))
    parser.add_argument("--calibration-fraction", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--device", default="auto")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()

    all_samples = load_primevul(args.train)
    train_samples, calibration_samples = split_train_calibration(
        all_samples, args.calibration_fraction, args.seed
    )
    if args.limit:
        train_samples = train_samples[: args.limit]
    args.output.mkdir(parents=True, exist_ok=True)
    records_path = args.output / "records.jsonl"
    completed, failed = prepare_scale_records(
        train_samples, load_mapping(args.mapping),
        args.output / "scale_cache.sqlite3", records_path,
    )
    records = load_records(records_path)
    parse_error_counts = []
    for record in records:
        match = re.search(r"parse_errors=(\d+)", record.scale_text.splitlines()[0])
        parse_error_counts.append(int(match.group(1)) if match else 0)
    _atomic_json(args.output / "dataset_manifest.json", {
        "source_rows": len(all_samples), "knowledge_rows_requested": len(train_samples),
        "calibration_rows_held_out": len(calibration_samples),
        "records_completed": completed, "records_failed": failed,
        "records_with_parse_errors": sum(count > 0 for count in parse_error_counts),
        "total_parse_error_nodes": sum(parse_error_counts),
        "seed": args.seed, "calibration_fraction": args.calibration_fraction,
        "test_data_indexed": False,
    })
    print(f"SCALE records: completed={completed}, failed={failed}")
    if args.prepare_only:
        return
    embedder = UniXcoderEmbedder(device=args.device)
    embeddings = embed_records_resumable(records_path, args.output, embedder, args.batch_size)
    sizes = build_faiss_indices(records_path, embeddings, args.output / "indices")
    print(f"FAISS partitions: {sizes}")


if __name__ == "__main__":
    _main()
