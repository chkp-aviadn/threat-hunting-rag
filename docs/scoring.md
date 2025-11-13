# Threat Scoring

## 1. Purpose
Produce a normalized 0–1 `threat_score` for each email combining semantic relevance to the query and heuristic feature indicators of phishing / fraud characteristics.

## 2. Inputs
| Input | Source | Notes |
|-------|--------|-------|
| Semantic similarity | Embedding cosine similarity (query ↔ email) | Normalized internally (raw & optional norm variant) |
| Urgent language | FeatureExtractor `detect_urgent_language` | Looks for urgency tokens/patterns (act now, immediate, urgent, expire) |
| Executive impersonation | FeatureExtractor heuristic | Name/title presence + authority phrasing |
| Suspicious attachment | File name patterns (invoice.exe, payment.zip) | High risk if executable / compressed & financial context |
| New sender / domain anomaly | Sender domain not in known baseline | Derived simple novelty check |
| Financial request | Keyword patterns (wire, transfer, invoice, payment) | Derived (weighted moderate) |
| Credential harvest | Password / account verification phrasing | Derived (weighted moderate) |
| Outside hours | Timestamp vs business hours heuristic | Lower weight (contextual) |

## 3. Feature Weights (Primary Signals)
Weights blended before final mapping (from code conventions):
- urgent_language: 0.30
- suspicious_attachment: 0.25
- executive_impersonation: 0.25
- new_sender (domain novelty): 0.20
Secondary derived signals (financial_request, credential_harvest, link_risk) contribute smaller boosts.

## 4. Composite Formula (Conceptual)
Pseudo-formula (illustrative, not exact code):
```
base = normalize(similarity_raw)
feature_sum = (0.30*urgent + 0.25*attachment + 0.25*impersonation + 0.20*new_sender)
secondary_bonus = 0.10*(financial + credential + link_risk average)
confidence = blend(feature_sum, base)
threat_score = clamp( 0.5*base + 0.4*feature_sum + 0.1*secondary_bonus )
```
Actual implementation also rounds and safely handles exceptions; confidence field provided separately for explanation.

## 5. Threat Levels
| Level | Score Range | Guidance |
|-------|-------------|----------|
| NEGLIGIBLE | < 0.20 | Typically ignore unless pattern emerges |
| LOW | 0.20–0.39 | Monitor; raise threshold for deeper triage |
| MEDIUM | 0.40–0.59 | Investigate sender & content context |
| HIGH | 0.60–0.79 | Treat as suspicious; verify out-of-band |
| CRITICAL | ≥ 0.80 | Escalate immediately; block / respond |

Threshold filtering uses `threat_threshold` to trim below desired risk level.

## 6. Confidence vs Score
`confidence` approximates reliability of the composite indicator mix (feature + similarity). It is distinct from `threat_score` which focuses on risk magnitude.

## 7. Explanation Structure
Each result produces:
- Overview (Threat Level, Score, Similarity, Confidence, Rank)
- Key Indicators (`name score – interpretation`)
- Risk Summary (one-line synthesis)
- Recommended Action (severity-based)
- Optional Analysis Detail (expanded indicator grouping)
If `explanation_mode="json"`, a structured dict is returned (see code in `rag_pipeline.py`).

## 8. Fallback Behavior
If explanation or feature extraction fails, pipeline provides minimal score + basic text reason. Threshold filtering still applies.

## 9. Customization
Adjust via environment or code:
- Swap embedding model (`EMBEDDING_MODEL`)
- Tweak weights in detection/scorer modules
- Modify level thresholds (mapping ranges) if tuning for different environments.

## 10. Future Improvements
| Idea | Benefit |
|------|---------|
| ML-based reranker | More nuanced prioritization under high volume |
| Statistical domain reputation | Penalize newly registered / low reputation domains |
| Temporal anomaly scoring | Spike detection across time windows |
| User feedback loop | Reinforce or adjust weights based on analyst actions |

---
This document reflects current heuristic scoring; monitor false positives/negatives and adjust weights incrementally.
