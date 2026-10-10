# Adaptive MulVul prototype

This repository contains a provider-independent prototype of two changes to
MulVul, plus an adapter for the public SCALE preprocessing design:

1. a class-conditionally calibrated, variable-size set of coarse CWE detector
   candidates; and
2. one evidence-guided reroute based on structured detector feedback.

The SCALE adapter follows the released two-stage design: optional LLM-generated
line semantics followed by Tree-Sitter structural serialization. It is an
integration layer for this project, not a claim of byte-identical reproduction
of the authors' batch output.

The prototype intentionally does not train or fine-tune an LLM. A concrete
Router, Detector, and evidence retriever can be connected through the protocols
in `src/adaptive_mulvul/interfaces.py`.

## Environment

```powershell
conda env create -f environment.yml
conda activate mulvul-adaptive
python -m pip install -e .
python -m pytest
```

No API secret is required for the included tests. Copy `.env.example` to a
local `.env` only after implementing a provider adapter; do not commit secrets.

## Runtime flow

1. The Router scores every coarse CWE category.
   The configured label space includes `benign` as an explicit safe-code exit.
2. The conformal calibrator creates a variable-size candidate set.
3. The controller calls the highest-ranked Detector first.
4. A Detector returns a typed decision, evidence strength, vulnerability
   conditions, and an optional alternative category.
5. The controller may move that alternative category to the front once.
6. By default, all calibrated candidates are checked because a sample may have
   multiple vulnerability labels. Deployments that explicitly prefer early
   exit can set `stop_on_stable_positive=True`.

## PrimeVul data check

The loader preserves vulnerable/fixed pairs and creates calibration partitions
by project and commit, preventing functions from the same security fix from
crossing the train/calibration boundary:

```powershell
python -m adaptive_mulvul.primevul data/train/primevul_train_paired.jsonl data/test/primevul_test_paired.jsonl
```

The coarse CWE map is generated from the versioned MITRE XML catalog and stores
the classification method, evidence, confidence, and dataset frequency for
every observed label in `config/cwe_coarse_mapping.json`.

It uses ten vulnerability categories plus the terminal `benign` label. This is
an auditable reconstruction because MulVul reports ten categories but does not
release its complete mapping table; see `config/README.md` for the boundary.

## Server knowledge-base build

Create the server environment and run the resumable pipeline:

```bash
conda env create -f environment-server.yml
conda activate mulvul-adaptive
python -m pip install -e .
python -m adaptive_mulvul.knowledge_base \
  --train data/train/primevul_train_paired.jsonl \
  --mapping config/cwe_coarse_mapping.json \
  --output artifacts/knowledge_base \
  --device auto \
  --batch-size 16
```

For a fast preflight that performs no model download or embedding, append
`--prepare-only --limit 20`. SCALE results are cached in SQLite; UniXcoder
embeddings have a batch checkpoint; neither the calibration partition nor test
data is indexed.

## Project layout

- `calibration.py`: class-conditional conformal thresholds and candidate sets.
- `uncertainty.py`: entropy and top-two margin reporting.
- `schemas.py`: structured Router/Detector messages and final trace.
- `controller.py`: sequential calls and one permitted reroute.
- `interfaces.py`: integration boundary for MulVul or any LLM provider.
- `mock_components.py`: deterministic local components for tests.
- `scale_transformer.py`: safe SCALE-style C/C++ transformation adapter.
- `primevul.py`: validated paired-data loader and leakage-safe calibration split.
- `cwe_mapping.py`: auditable MITRE-hierarchy-based coarse-category generator.
- `knowledge_base.py`: resumable SCALE, UniXcoder, FAISS, and contrastive retrieval pipeline.

The official SCALE research repository is retained under
`third_party/Comment4Vul`. Its legacy prompt scripts were excluded because they
contained historical embedded credentials, and the upstream repository does
not currently include a root license. See `THIRD_PARTY.md` before redistribution.

The next integration step is to implement adapters for MulVul's global
UniXcoder/FAISS retrieval and its evolved production prompts. No official
MulVul prompt-evolution implementation was found during the current source
audit, so the project does not label a speculative reimplementation as
upstream code.
