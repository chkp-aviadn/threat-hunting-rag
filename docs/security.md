# Security (Essential Baseline)

This file lists only MUST-have current measures required for a minimally safe deployment of the phishing threat hunting system. All advisory / future / recommended sections have been removed.

## 1. Current Mandatory Controls
| Control | Status | Rationale |
|---------|--------|-----------|
| API Key header (`X-API-Key`) | Enabled (static demo key) | Prevent completely unauthenticated access |
| Input length limit (`max_query_length`) | Enforced | Mitigates trivial oversized payload DoS |
| Basic input sanitization (`enable_input_sanitization`) | Enabled | Reduces risk of log / downstream injection |
| Session separation (UUID per chat) | Implemented | Prevents cross-user conversation bleed |
| Audit log path configured (`audit_log_path`) | Available | Allows security event recording |
| Environment segregation (`.env.example` not committed secrets) | Practiced | Avoids hard‑coding secrets in VCS |

## 2. Core Threats Considered
| Threat | Immediate Control |
|--------|------------------|
| API key leakage | Manual key rotation (external to code) |
| Oversized / abusive queries | Length limit + optional rate settings |
| Prompt manipulation | Basic sanitization + review of explanations |
| Cache misuse / poisoning | TTL + LRU on query cache; can purge via reset |
| Session hijack (guessable IDs) | UUID v4 non-guessable identifiers |

## 3. Essential Operational Procedures
| Procedure | Action |
|-----------|--------|
| Rotate demo key before non-local use | Set `API_KEY` env var to a strong secret |
| Purge caches after scoring logic changes | Run `make full-reset` |
| Check audit log integrity | Ensure writable only by service user |
| Limit network exposure | Bind API behind reverse proxy / TLS terminator |

## 4. Minimal Deployment Checklist (All Required)
1. Replace demo API key with strong secret (`API_KEY` env).
2. Run behind HTTPS (TLS termination or reverse proxy).
3. Enforce input length limit (already default) – do not disable.
4. Restrict file system permissions: logs & cache directories not world-writable.
5. Use non-root user in container / process.
6. Set resource limits (CPU/memory) to prevent exhaustion.
7. Keep dependencies updated (run `make bootstrap` after updates).

## 5. Incident Essentials
| Event | Immediate MUST Action |
|-------|-----------------------|
| Key exposure | Replace key, restart service, invalidate old key immediately |
| Sudden query flood | Temporarily block offending source (network / WAF) |
| Cache corruption errors | Flush caches (`make full-reset`) and restart |
| Unexpected explanation anomalies | Review logs; verify feature extractor integrity; redeploy if tampered |

## 6. Data Handling (Required Baseline)
Although dataset is synthetic, treat any real ingestion as sensitive:
- Do not log full email bodies (truncate to necessary snippet).
- Do not commit real emails or secrets to version control.
- If real data introduced, ensure disk encryption outside application scope.

---
Only mandatory baseline items are retained. Add advanced hardening in staging before production.
