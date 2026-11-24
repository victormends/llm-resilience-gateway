# llm-resilience-gateway

Zero-dependency Node.js (`>=22`, pure ESM) HTTP gateway and guardrail toolkit for resilient multi-provider LLM inference. Demonstrated with an **Incident Triage & Severity Classification** pipeline (`P1` / `P2` / `P3`) featuring semantic circuit-breaker cooldowns, `Retry-After` threshold skipping, sticky fallback promotion, cached-token USD cost tracking with automatic economy-tier downgrade, XML-fenced prompt-injection isolation, strict JSON Schema validation, and deterministic destructive-action blocking.

## Architecture

```text
Client Request (POST /triage | GET /health?probe=1 | GET /budget)
  │
  ├─► Ingress Guard (127.0.0.1 bind, 32 KiB body limit, Origin allowlist, secret redaction)
  │
  ├─► CostGuard Ledger (src/cost_guard.mjs)
  │     ├─ Hard ceiling check (optional hardStopLimitUsd -> HTTP 429)
  │     └─ Soft ceiling check (costSafetyLimitUsd -> auto-downgrade to economy tier)
  │
  ├─► CooldownStore & Sticky Router (src/cooldown.mjs, src/gateway.mjs)
  │     ├─ Skips routes in active cooldown (6h credential/quota vs 15m transient)
  │     ├─ Evaluates Retry-After (>30s -> immediate fallback skip; <=30s -> bounded retry)
  │     └─ Promotes healthy fallback via sticky routing until primary recovery probe
  │
  ├─► Prompt Boundary Isolation (src/guardrails.mjs)
  │     └─ promptSafeJson() escapes <, >, & inside <incident_context_json> / <event_payload_json>
  │
  └─► Post-Inference Guardrails (src/guardrails.mjs)
        ├─ Destructive action & shell/SQL command blocker (DESTRUCTIVE_ACTION_BLOCKED)
        ├─ Strict JSON Schema validator (additionalProperties: false, catalog enums)
        └─ Deterministic incident policy calibration (P1 security/blast-radius, non-prod cap)
```

## Policy Matrix: Semantic Cooldown vs. Budget Guardrail

### 1. Semantic Failure Classification & Circuit Breaker (`src/cooldown.mjs`)

| Signal / HTTP Status | Semantic Class | Default Cooldown | `Retry-After` Behavior | Gateway Action |
| :--- | :--- | :--- | :--- | :--- |
| `401`, `403`, `auth_unavailable`, `validation_required`, `token expired` | `credential_or_quota` | `6h` (`21,600,000 ms`) | Never retries same route | Immediate skip to next candidate in `MODEL_CHAIN` |
| `429`, `RESOURCE_EXHAUSTED`, `rate_limit`, `quota` | `credential_or_quota` | `max(6h, Retry-After)` | `<= 30s`: 1 bounded retry; `> 30s` or absent: immediate skip | Cools down route on exhaustion or threshold exceeded |
| `408`, `500`, `502`, `503`, `504`, `AbortError`, `ECONNREFUSED` | `transient` | `15m` (`900,000 ms`) | `<= 30s`: 1 bounded retry; `> 30s`: immediate skip | Cools down route for 15m after failure |
| `400`, `404`, `422`, `INVALID_MODEL_JSON`, `GuardrailError` | `null` (no route penalty) | `0 ms` | N/A | Rejects unsafe/invalid completion and tries fallback without poisoning healthy route |

### 2. Budget Guardrail & Auto-Downgrade (`src/cost_guard.mjs`)

| Mechanism | Trigger Condition | Behavior |
| :--- | :--- | :--- |
| Token & Cached-Token Accounting | Every completed upstream call | Separates `cachedTokens` from `uncachedPromptTokens` (`promptTokens - cachedTokens`) and prices per-model rates (`inputPer1M`, `cachedInputPer1M`, `outputPer1M`). |
| Soft Safety Limit (`costSafetyLimitUsd`) | `totalEstimatedCostUsd >= costSafetyLimitUsd` (default `$0.35`) | Trips `downgradeActive = true`; subsequent calls restrict candidate selection to `tier: "economy"` (or lowest-cost model). |
| Hard Stop Ceiling (`hardStopLimitUsd`) | Optional ceiling reached | Fails closed prior to upstream dispatch with `BudgetLimitError` (`HTTP 429`, `BUDGET_HARD_LIMIT_EXCEEDED`). |

### 3. Incident Triage Guardrails (`src/guardrails.mjs`)

- **XML Boundary Escaping**: `promptSafeJson()` converts `<`, `>`, and `&` to `\u003c`, `\u003e`, and `\u0026` inside `<incident_context_json>` and `<event_payload_json>`.
- **Destructive Command Blocking**: Rejects destructive `recommendedAction` identifiers (`drop_*`, `delete_*`, `truncate_*`, `destroy_*`, `kill_*`, `reboot_*`) and dangerous SQL/shell payloads (`DROP TABLE`, `TRUNCATE TABLE`, `rm -rf`, `kubectl delete`, `terraform destroy`, `kill -9`) in model outputs while preserving benign audit-log alerts in inputs.
- **Strict JSON Schema**: Rejects unknown properties (`additionalProperties: false`), missing required fields, summary length violations (`5..320`), and out-of-catalog `severity`, `category`, `incidentType`, or `recommendedAction` values.
- **Deterministic Calibration**: Escalates production `credential_leak` and multi-tenant critical outages to `P1` with `requiresHumanApproval: true`, caps `staging`/`sandbox`/`dev` events to `P3`, and normalizes cross-field taxonomy.

## Quickstart

Requires Node.js `>=22` (tested on `v26.12.1`) with zero external npm dependencies.

```bash
# Syntax verification across source and evaluation modules
npm run check

# Run unit, integration, HTTP, and leak-audit tests
npm test

# Run deterministic offline resilience & guardrail benchmark
npm run eval
```

Start the local HTTP gateway (`127.0.0.1:8420` by default):

```bash
npm start
```

### HTTP Endpoints

- `GET /health` — Returns current `MODEL_CHAIN` status, cooldown state, sticky fallback status, and cost ledger summary.
- `GET /health?probe=1` — Single-flight preflight connectivity probe across `/v1/models` and minimal completion checks (concurrent requests share one in-flight probe).
- `GET /health?refresh=1` — Clears cooldown state and sticky fallback promotion before returning snapshot.
- `GET /budget` — Returns normalized token counts, cache hit rate, per-model spend, and downgrade state.
- `POST /triage` — Accepts an incident JSON payload (`<= 32 KiB`) and returns schema-validated, policy-calibrated triage output.

Example request:

```bash
curl -s -X POST http://127.0.0.1:8420/triage \
  -H "Content-Type: application/json" \
  -d '{
    "eventId": "evt-401",
    "service": "orders-postgres",
    "environment": "production",
    "region": "us-east-1",
    "message": "Primary WAL disk usage at 99% causing write stalls across all tenants."
  }'
```

## Project Layout

- `src/cooldown.mjs` — Semantic failure classifier, `Retry-After` parser, and `CooldownStore` circuit breaker.
- `src/cost_guard.mjs` — Cached/uncached token ledger, USD cost calculator, and auto-downgrade engine.
- `src/guardrails.mjs` — Secret redaction, `promptSafeJson()`, strict JSON Schema validator, destructive action blocker, and deterministic triage policy.
- `src/gateway.mjs` — Local `127.0.0.1` HTTP gateway, injectable transport abstraction, `MODEL_CHAIN` failover, sticky fallback promotion, and single-flight health probing.
- `eval/run_benchmark.mjs` — Deterministic offline benchmark measuring raw vs. post-guardrail accuracy, concurrent `stabilityRate`, median/P95 latency, cooldown skips, and unsafe output blocking.
- `tests/*.test.mjs` — Built-in `node:test` test suite covering cooldowns, cost guard, guardrails, HTTP gateway contracts, and benchmark reproducibility.

## License

MIT — see [LICENSE](LICENSE).
