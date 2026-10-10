# CWE coarse-category mapping

`cwe_coarse_mapping.json` covers every numeric CWE observed in the supplied
PrimeVul paired train and test files. It was generated from MITRE CWE 4.20.

The MulVul paper states that its full experiment uses ten coarse vulnerability
categories but does not publish the complete CWE-to-category table. Figure 6
shows only a shortened prompt example. Consequently, this mapping is an
independent, reproducible reconstruction and must not be described as the
authors' original mapping.

The ten vulnerability categories are memory, injection, input, numeric,
resource, concurrency, access, crypto, information, and logic. `benign` is a
separate terminal label for fixed/non-vulnerable samples.

Each mapping decision records its method, evidence, confidence, and frequency
in the supplied dataset. Cross-cutting CWEs use explicit documented overrides;
all other decisions use exact roots, ancestors in MITRE's Research Concepts
view, or textual signals. Regenerate it with:

```powershell
python -m adaptive_mulvul.cwe_mapping `
  --catalog data/cwe/v4.20/cwec_v4.20.xml `
  --dataset data/train/primevul_train_paired.jsonl `
  --dataset data/test/primevul_test_paired.jsonl `
  --output config/cwe_coarse_mapping.json
```
