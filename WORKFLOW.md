# Adaptive MulVul workflow

## Offline calibration

1. Split labelled data into training, calibration, and test partitions.
2. Keep the original MulVul knowledge-base and prompt-evolution preparation.
3. Run the Router on every calibration sample and save the score of every
   coarse CWE category.
4. For each true category, calculate its class-conditional conformal
   nonconformity scores and quantile threshold.
5. Save the fitted thresholds. No LLM parameter is trained in this stage.

## Online detection

1. Convert the target code with the SCALE-style adapter (LLM line semantics are
   optional), then retrieve global examples when a MulVul knowledge base is
   available.
2. Ask the Router to score every configured coarse category.
   The generated label space contains ten vulnerability categories and must
   include `benign` so safe code has an explicit route.
3. Normalize the scores and apply the fitted class-conditional thresholds.
   The retained category set is the sample-specific dynamic Top-k.
4. Call the highest-ranked category Detector with contrastive evidence.
   `benign` is a terminal routing label and never invokes a Detector.
5. Require structured feedback: positive/negative/abstain, confidence,
   evidence support, vulnerability conditions, defensive checks, and one
   optional alternative category.
6. If an alternative category is returned, move it to the front of the queue
   once. Detectors never communicate directly.
7. Continue through the calibrated candidate queue. A feedback-inserted
   category may be checked even when it was absent from the initial set.
8. Aggregate unique CWE predictions and retain the full routing trace for
   evaluation and error analysis.

## Current implementation boundary

Implemented now: SCALE-style C/C++ transformation, score validation, score
normalization, uncertainty metrics, class-conditional conformal candidate sets,
sequential controller, structured feedback, one reroute, OpenAI-compatible
Router/Detector adapters, mocks, and tests.

Still requiring upstream MulVul assets: UniXcoder/FAISS knowledge base,
PrimeVul data loaders, evolved production prompts, and the full evaluation
harness. These were not present in an official public MulVul repository found
during the current audit.
