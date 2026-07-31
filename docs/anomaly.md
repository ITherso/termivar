# Anomaly detection

The anomaly module compares response characteristics and produces heuristic scores and severity classes. It is Experimental.

## Inputs

The model can use response status, body size, timing, headers, and content indicators. Callers must normalize observations and preserve enough evidence for manual review.

## Outputs

An anomaly score is a signal, not a confirmed vulnerability. Reports should distinguish observed evidence, heuristic interpretation, and final finding severity.

## False positives

Dynamic pages, rate limiting, personalization, caching, geographic routing, and unstable targets can all create anomalous responses. Baselines should contain multiple samples, and timing-sensitive conclusions should use controlled repetition.

## Design rules

- Keep scoring deterministic for the same normalized input.
- Version scoring behavior when weights or thresholds change.
- Store evidence alongside scores.
- Never let anomaly output bypass authorization or rate limits.
- Evaluate precision and recall on a documented corpus before calling a model stable.
