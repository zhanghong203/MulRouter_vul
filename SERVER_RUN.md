# Server run guide

The long-running stage builds a MulVul-style example knowledge base from the
leakage-safe training partition. It never indexes the held-out calibration
partition or the test file.

## 1. Upload

Upload the repository except `.env`, `artifacts/`, `.cache/`, `tmp/`, and
`__pycache__/`. The required inputs are:

- `data/train/primevul_train_paired.jsonl`
- `config/cwe_coarse_mapping.json`
- source code and `environment-server.yml`

Create `.env` directly on the server only when API inference is needed. The
knowledge-base build below does not use an API key.

## 2. Environment and preflight

```bash
conda env create -f environment-server.yml
conda activate mulvul-adaptive
python -m pip install -e .
python -m pytest -q
python -m adaptive_mulvul.knowledge_base \
  --train data/train/primevul_train_paired.jsonl \
  --mapping config/cwe_coarse_mapping.json \
  --output artifacts/kb_preflight \
  --prepare-only --limit 20
```

The preflight should report 20 completed records and zero failed records.

## 3. Full build

```bash
python -m adaptive_mulvul.knowledge_base \
  --train data/train/primevul_train_paired.jsonl \
  --mapping config/cwe_coarse_mapping.json \
  --output artifacts/knowledge_base \
  --device auto \
  --batch-size 16
```

On GPU memory errors, lower `--batch-size` to 8, 4, or 2. On a CPU-only host,
`--device auto` uses CPU. Re-running the same command resumes SCALE conversion
from SQLite and UniXcoder embedding from `embedding_state.json`.

## 4. Expected artifacts

- `records.jsonl`: SCALE representations and labels
- `scale_cache.sqlite3`: resumable transformation cache
- `embeddings.npy`: normalized UniXcoder vectors
- `embedding_state.json`: embedding checkpoint
- `indices/global.faiss`: Router global index
- `indices/benign.faiss`: fixed-code counterexamples
- `indices/vulnerable.faiss`: cross-category hard-negative source
- `indices/category_*.faiss`: category-specific positive pools
- `indices/*.ids.npy`: mapping from FAISS positions to records
- `dataset_manifest.json` and `indices/manifest.json`: audit metadata

Do not use the test file as a knowledge-base input.
