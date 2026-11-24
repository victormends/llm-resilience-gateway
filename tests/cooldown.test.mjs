import test from "node:test";
import assert from "node:assert/strict";

import {
  CooldownStore,
  DEFAULT_CREDENTIAL_COOLDOWN_MS,
  DEFAULT_RETRY_AFTER_SKIP_THRESHOLD_MS,
  DEFAULT_TRANSIENT_COOLDOWN_MS,
  classifyFailure,
  parseRetryAfterMs,
  routeKey
} from "../src/cooldown.mjs";

test("semantic classifier puts 401/403/429 and auth/quota messages into 6h cooldown", () => {
  assert.equal(DEFAULT_CREDENTIAL_COOLDOWN_MS, 6 * 60 * 60_000);
  assert.equal(DEFAULT_TRANSIENT_COOLDOWN_MS, 15 * 60_000);
  assert.equal(DEFAULT_RETRY_AFTER_SKIP_THRESHOLD_MS, 30_000);

  for (const upstreamStatus of [401, 403, 429]) {
    const result = classifyFailure({ upstreamStatus, message: "upstream rejected" });
    assert.equal(result.kind, "credential_or_quota");
    assert.equal(result.durationMs, DEFAULT_CREDENTIAL_COOLDOWN_MS);
    assert.equal(result.skipToFallback, true);
  }

  for (const message of [
    "auth_unavailable: no active provider credentials",
    "RESOURCE_EXHAUSTED: quota exceeded for project",
    "Rate limit reached on upstream tier",
    "validation_required: verify your account",
    "Provider token expired"
  ]) {
    const result = classifyFailure({ statusCode: 503, message });
    assert.equal(result.kind, "credential_or_quota");
    assert.equal(result.durationMs, DEFAULT_CREDENTIAL_COOLDOWN_MS);
    assert.equal(result.skipToFallback, true);
  }
});

test("semantic classifier puts 408/5xx/timeouts into 15m cooldown without cooling 400/422", () => {
  for (const statusCode of [408, 500, 502, 503, 504]) {
    const result = classifyFailure({ statusCode, message: "upstream unavailable" });
    assert.equal(result.kind, "transient");
    assert.equal(result.durationMs, DEFAULT_TRANSIENT_COOLDOWN_MS);
  }

  const timeoutResult = classifyFailure(Object.assign(new Error("aborted"), { name: "AbortError" }));
  assert.equal(timeoutResult.kind, "transient");
  assert.equal(timeoutResult.durationMs, DEFAULT_TRANSIENT_COOLDOWN_MS);
  assert.equal(timeoutResult.reason, "upstream_timeout");

  const forced = classifyFailure(new Error("empty preflight"), { forceTransient: true });
  assert.equal(forced.kind, "transient");
  assert.equal(forced.durationMs, DEFAULT_TRANSIENT_COOLDOWN_MS);

  for (const statusCode of [400, 404, 422]) {
    const clientErr = classifyFailure({ statusCode, message: "schema validation error" });
    assert.equal(clientErr.kind, null);
    assert.equal(clientErr.durationMs, 0);
  }
});

test("Retry-After parser handles seconds, decimals, HTTP-date, and threshold skipping", () => {
  const nowMs = Date.parse("2026-11-24T12:00:00.000Z");
  assert.equal(parseRetryAfterMs("45", nowMs), 45_000);
  assert.equal(parseRetryAfterMs("12.5", nowMs), 12_500);
  assert.equal(parseRetryAfterMs("Tue, 24 Nov 2026 12:02:00 GMT", nowMs), 120_000);
  assert.equal(parseRetryAfterMs("invalid-date", nowMs), null);
  assert.equal(parseRetryAfterMs("", nowMs), null);

  // Above 30s threshold -> immediate skip to fallback
  const longRateLimit = classifyFailure({
    upstreamStatus: 429,
    headers: { "retry-after": "90" },
    message: "Too many requests"
  }, { nowMs });
  assert.equal(longRateLimit.skipToFallback, true);
  assert.equal(longRateLimit.shouldRetrySameRoute, false);
  assert.equal(longRateLimit.retryAfterMs, 90_000);
  assert.equal(longRateLimit.reason, "retry_after_exceeds_threshold");

  // Within 30s threshold -> short same-route retry allowed on 429/503
  const shortRateLimit = classifyFailure({
    upstreamStatus: 429,
    headers: { "retry-after": "5" },
    message: "Rate limit hit"
  }, { nowMs });
  assert.equal(shortRateLimit.skipToFallback, false);
  assert.equal(shortRateLimit.shouldRetrySameRoute, true);
  assert.equal(shortRateLimit.retryDelayMs, 5_000);

  // Never retry 401 on same route even with tiny Retry-After
  const authWithRetryAfter = classifyFailure({
    upstreamStatus: 401,
    headers: { "retry-after": "1" },
    message: "Invalid credentials"
  }, { nowMs });
  assert.equal(authWithRetryAfter.skipToFallback, true);
  assert.equal(authWithRetryAfter.shouldRetrySameRoute, false);
});

test("CooldownStore manages circuit breaker lifecycle with deterministic clock and secret redaction", () => {
  let clock = 1_000_000;
  const store = new CooldownStore({ now: () => clock });
  const candidate = { provider: "gemini", endpoint: "primary", model: "gemini-2.5-pro" };

  assert.equal(routeKey(candidate), "gemini:primary:gemini-2.5-pro");
  assert.equal(store.isCoolingDown(candidate), false);

  const { state } = store.markUnavailable(
    candidate,
    { upstreamStatus: 401, message: "Rejected Authorization: Bearer secret_token_12345" },
    42
  );
  assert.equal(state.cooldownKind, "credential_or_quota");
  assert.equal(state.error.message, "Rejected Authorization: <redacted>");
  assert.doesNotMatch(state.error.message, /secret_token_12345/);
  assert.equal(store.isCoolingDown(candidate), true);
  assert.equal(store.remainingMs(candidate), DEFAULT_CREDENTIAL_COOLDOWN_MS);

  clock += DEFAULT_CREDENTIAL_COOLDOWN_MS - 1;
  assert.equal(store.isCoolingDown(candidate), true);
  assert.equal(store.remainingMs(candidate), 1);

  clock += 1;
  assert.equal(store.isCoolingDown(candidate), false);
  assert.equal(store.remainingMs(candidate), 0);

  store.markReady(candidate, 18);
  assert.equal(store.getState(candidate).status, "ready");
  assert.equal(store.snapshot().length, 1);

  store.reset(candidate);
  assert.equal(store.getState(candidate), null);
});

test("CooldownStore preserves newer unavailable state against older in-flight markReady", () => {
  let clock = 10_000;
  const store = new CooldownStore({ now: () => clock });
  const candidate = { provider: "gemini", endpoint: "p1", model: "gemini-2.5-pro" };

  const staleRequestStart = clock;
  clock += 5;
  store.markUnavailable(candidate, { upstreamStatus: 429, message: "Rate limit" }, 5);
  assert.equal(store.isCoolingDown(candidate), true);

  clock += 5;
  store.markReady(candidate, 10, staleRequestStart);
  assert.equal(store.getState(candidate).status, "unavailable");
  assert.equal(store.isCoolingDown(candidate), true);
});

test("CooldownStore supports custom cooldown durations and full reset", () => {
  let clock = 50_000;
  const store = new CooldownStore({
    credentialCooldownMs: 120_000,
    transientCooldownMs: 15_000,
    now: () => clock
  });
  const a = { provider: "a", model: "m1" };
  const b = { provider: "b", model: "m2" };

  store.markUnavailable(a, { upstreamStatus: 403, message: "Forbidden" });
  store.markUnavailable(b, { upstreamStatus: 502, message: "Bad gateway" });
  assert.equal(store.remainingMs(a), 120_000);
  assert.equal(store.remainingMs(b), 15_000);
  assert.equal(store.snapshot().length, 2);

  store.reset();
  assert.equal(store.snapshot().length, 0);
  assert.equal(store.isCoolingDown(a), false);
});
