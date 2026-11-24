# llm-resilience-gateway

A zero-dependency Node.js (`>=22`, ESM) loopback HTTP gateway and deterministic guardrail harness for multi-provider LLM calls.

---

## Why This Exists

Calling external LLM APIs from automation tools fails in ways naive retry loops make worse:

1. A `401` credential error or `429` quota exhaustion does not recover in 5 seconds; retrying it repeatedly wastes latency while a transient `503` should not ban a provider for 6 hours.
2. Retries and fallback loops silently burn through monthly budgets unless token spend triggers an automatic economy-tier downgrade.
3. Passing untrusted operational text directly into a prompt exposes downstream handlers to XML boundary breakouts or hallucinated destructive shell/SQL actions.

`llm-resilience-gateway` keeps those failure modes separated: semantic circuit-breaker cooldowns (`6h` credential/quota vs `15m` transient), `Retry-After` threshold skipping, sticky fallback routing, cached-token USD cost tracking with automatic economy downgrade, XML-escaped prompt isolation, strict JSON Schema validation, and a deterministic policy engine shown here on an incident triage workflow (`P1` / `P2` / `P3`).

## Origin & Sanitization

The failover chain, semantic cooldown classifier, single-flight preflight probe, cost ledger, and XML boundary escaping were extracted and rewritten from a private internal automation gateway. All client-specific workflows, browser extensions, credentials, and domain fixtures were removed, leaving the standalone gateway, an offline mock upstream mode, and a synthetic incident-triage evaluation harness.

## What It Intentionally Does Not Do

This is a single-process loopback gateway and testing harness, not a distributed edge proxy.

It does **not**:

- persist billing ledgers across process restarts (cost accounting is kept in process memory)
- execute shell, Kubernetes, Terraform, or SQL actions automatically (triage output is advisory JSON only)
- serve multi-tenant public Internet traffic (binds to `127.0.0.1` and enforces a loopback `Host` header allowlist against DNS rebinding)

---

## Architecture

```text
Client Request (POST /triage | GET /health?probe=1 | GET /budget)
  |
  +-> Ingress Guard (127.0.0.1 bind, Host allowlist, 32 KiB limit, Origin check, secret redaction)
  |
  +-> CostGuard Ledger (src/cost_guard.mjs)
  |     |-- Hard ceiling check (optional hardStopLimitUsd -> HTTP 429)
  |     +-- Soft ceiling check (costSafetyLimitUsd -> auto-downgrade to economy tier)
  |
  +-> CooldownStore & Sticky Router (src/cooldown.mjs, src/gateway.mjs)
  |     |-- Skips routes in active cooldown (6h credential/quota vs 15m transient)
  |     |-- Evaluates Retry-After (>30s -> immediate fallback skip; <=30s -> bounded retry)
  |     +-- Promotes healthy fallback via sticky routing until primary recovery probe
  |
  +-> Prompt Boundary Isolation (src/guardrails.mjs)
  |     +-- promptSafeJson() escapes <, >, & inside <incident_context_json> / <event_payload_json>
  |
  +-> Post-Inference Guardrails (src/guardrails.mjs)
        |-- Destructive action & shell/SQL blocker (DESTRUCTIVE_ACTION_BLOCKED)
        |-- Strict JSON Schema validator (additionalProperties: false, catalog enums)
        +-- Deterministic incident policy calibration (P1 escalation, non-prod severity cap)
```

---

## Policy Matrix: Semantic Cooldown vs. Budget Guardrail

### 1. Semantic Failure Classification (`src/cooldown.mjs`)

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
- **Destructive Command Blocking**: Rejects destructive `recommendedAction` identifiers (`drop_*`, `delete_*`, `truncate_*`, `destroy_*`, `kill_*`, `reboot_*`) and dangerous SQL/shell payloads (`DROP TABLE`, `TRUNCATE TABLE`, `rm -rf`, `kubectl delete`, `terraform destroy`, `kill -9`) in model outputs while preserving benign audit-log strings in inputs.
- **Strict JSON Schema**: Rejects unknown properties (`additionalProperties: false`), missing required fields, summary length violations (`5..320`), and out-of-catalog enum values.
- **Deterministic Calibration**: Escalates production `credential_leak` and multi-tenant outages to `P1` with `requiresHumanApproval: true`, caps `staging`/`sandbox`/`dev` events to `P3`, and aligns category/type taxonomy.

---

## Quickstart

Requires **Node.js >= 22 LTS** (verified in CI on Node 22 and 24) with zero external npm dependencies.

```bash
npm run check
npm test
npm run eval
```

## Measured Offline Eval Results

Output from `npm run eval` (`node eval/run_benchmark.mjs`, `seed=20261124`, `12` scenarios x `3` repeats = `36` requests at concurrency `4`):

| Metric | Measured Value | Notes |
| :--- | :--- | :--- |
| Requests Succeeded | `36 / 36` (`0` failed) | All faulted/blocked requests recovered via failover |
| Raw vs. Post-Guardrail Accuracy | `0.50` -> `1.00` (`+0.50`) | Deterministic policy & strict JSON schema calibration |
| Scenario Stability Rate | `1.00` (`12 / 12` scenarios) | Identical output across concurrent repeats |
| Median / P95 Latency | `18.61 ms` / `25.21 ms` | Total benchmark wall time: `199 ms` |
| Failover & Cooldown Skips | `27` fallbacks, `8` cooldown skips | `4` rate limits, `1` transient, `3` guardrail blocks injected |
| Economy-Tier Routed Calls | `15` requests | Triggered by `downgradeActive: true` (`costSafetyLimitUsd=$0.095`) |
| Destructive Blocks / Unsafe Leaks | `2` blocked / `0` leaks | `destructiveAttemptsBlocked: 2`, `unsafeLeakCount: 0` |
| Prompt Cache Hit Rate / Cost | `21.05%` (`$0.112702` total) | `36,000 / 171,000` cached prompt tokens |

Start the local HTTP gateway (`127.0.0.1:8420` by default) in **built-in mock mode** (no API keys needed) or upstream proxy mode:

```bash
npm run start:mock
```

### HTTP Endpoints

- `GET /health`: returns current `MODEL_CHAIN` status, cooldown state, sticky fallback status, and cost ledger summary
- `GET /health?probe=1`: single-flight preflight connectivity probe across `/v1/models` and minimal completion checks (concurrent requests share one in-flight probe)
- `GET /health?refresh=1`: clears cooldown state and sticky fallback promotion before returning snapshot
- `GET /budget`: returns normalized token counts, cache hit rate, per-model spend, and downgrade state
- `POST /triage`: accepts an incident JSON payload (`<= 32 KiB`) and returns schema-validated triage output

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

- `src/cooldown.mjs`: semantic failure classifier, `Retry-After` parser, and `CooldownStore` circuit breaker
- `src/cost_guard.mjs`: cached/uncached token ledger, USD cost calculator, and auto-downgrade engine
- `src/guardrails.mjs`: secret redaction, `promptSafeJson()`, strict JSON Schema validator, destructive action blocker, and deterministic triage policy
- `src/gateway.mjs`: local `127.0.0.1` HTTP gateway, Host allowlist, injectable transport abstraction, `MODEL_CHAIN` failover, sticky fallback promotion, and single-flight health probing
- `eval/run_benchmark.mjs`: offline benchmark measuring raw vs. post-guardrail accuracy, concurrent `stabilityRate`, median/P95 latency, cooldown skips, and unsafe output blocking
- `tests/*.test.mjs`: built-in `node:test` test suite covering cooldowns, cost guard, guardrails, HTTP gateway contracts, and benchmark reproducibility

## License

MIT - see [LICENSE](LICENSE).
