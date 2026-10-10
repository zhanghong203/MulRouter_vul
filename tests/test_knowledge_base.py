import json

import pytest

from adaptive_mulvul.knowledge_base import load_records, prepare_scale_records
from adaptive_mulvul.primevul import PrimeVulSample


class CountingTransformer:
    def __init__(self):
        self.calls = 0

    def transform(self, code, language="c"):
        self.calls += 1
        return f"[SCALE language={language}]\n{code}"


def _sample(idx, target, function_hash):
    return PrimeVulSample(
        idx=idx,
        project="demo",
        commit_id="abc",
        target=target,
        function=f"int f{idx}(void) {{ return {target}; }}",
        function_hash=function_hash,
        cwes=("CWE-119",),
        cve="CVE-demo",
        file_name="demo.c",
    )


def test_scale_record_cache_resumes_and_fixed_sample_is_benign(tmp_path):
    samples = (_sample(1, 1, "vuln"), _sample(2, 0, "fixed"))
    cache = tmp_path / "scale.sqlite3"
    output = tmp_path / "records.jsonl"
    transformer = CountingTransformer()

    assert prepare_scale_records(
        samples, {"CWE-119": "memory"}, cache, output, transformer
    ) == (2, 0)
    assert transformer.calls == 2
    assert prepare_scale_records(
        samples, {"CWE-119": "memory"}, cache, output, transformer
    ) == (2, 0)
    assert transformer.calls == 2

    records = load_records(output)
    assert records[0].categories == ("memory",)
    assert records[1].categories == ("benign",)
    assert json.loads(output.read_text().splitlines()[0])["record_id"]


def test_embedding_checkpoint_faiss_build_and_retrieval(tmp_path):
    np = pytest.importorskip("numpy")
    pytest.importorskip("faiss")
    from adaptive_mulvul.knowledge_base import (
        FaissEvidenceRetriever,
        build_faiss_indices,
        embed_records_resumable,
    )

    class FakeEmbedder:
        model_name = "fake-embedder"

        def encode(self, texts, batch_size):
            rows = []
            for text in texts:
                rows.append([float("return 1" in text), float("return 0" in text), 0.5])
            return np.asarray(rows, dtype="float32")

    samples = (_sample(1, 1, "vuln"), _sample(2, 0, "fixed"))
    records_path = tmp_path / "records.jsonl"
    prepare_scale_records(
        samples, {"CWE-119": "memory"}, tmp_path / "cache.sqlite3",
        records_path, CountingTransformer(),
    )
    embedder = FakeEmbedder()
    embeddings = embed_records_resumable(records_path, tmp_path, embedder, batch_size=1)
    sizes = build_faiss_indices(records_path, embeddings, tmp_path / "indices")
    retriever = FaissEvidenceRetriever(records_path, tmp_path / "indices", embedder)

    assert sizes == {"global": 2, "benign": 1, "vulnerable": 1, "category_memory": 1}
    assert "CWE-119" in retriever.global_evidence("return 1")[0]
    contrast = retriever.category_evidence("return 1", "memory")
    assert any("IN-CATEGORY POSITIVE" in item for item in contrast)
    assert any("BENIGN COUNTEREXAMPLE" in item for item in contrast)
