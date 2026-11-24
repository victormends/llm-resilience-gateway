import test from "node:test";
import assert from "node:assert/strict";

import { CooldownStore } from "../src/cooldown.mjs";
import { CostGuard } from "../src/cost_guard.mjs";
import { MAX_REQUEST_BODY_BYTES, createGateway } from "../src/gateway.mjs";

function makeTriageJson(overrides = {}) {
  return JSON.stringify({
    severity: "P2",
    category: "database",
    incidentType: "connection_exhaustion",
    recommendedAction: "capture_connection_pool_metrics",
    requiresHumanApproval: false,
    summary: "Connection pool saturation reached 92 percent on primary writer.",
    ...overrides
  });
}

test("creating gateway never auto-binds a port on import/instantiation", () => {
  const gw = createGateway({ logger: () => {} });
  assert.equal(gw.server.listening, false);
});

test("gateway fails over across MODEL_CHAIN, cools down 401 for 6h, and promotes sticky fallback", async () => {
  let clock = 10_000_000;
  const calls = [];
  const gw = createGateway({
    now: () => clock,
    sleep: async () => {},
    logger: () => {},
    modelChain: [
      { role: "primary", provider: "gemini", endpoint: "p1", model: "gemini-2.5-pro", tier: "primary", structuredOutput: true },
      { role: "fallback_standard", provider: "openai", endpoint: "p2", model: "gpt-4.1-mini", tier: "standard", structuredOutput: true }
    ],
    transport: {
      async listModels(_ep, candidates) {
        return { ok: true, models: new Set(candidates.map((c) => c.model)) };
      },
      async complete(candidate) {
        calls.push(candidate.model);
        if (candidate.model === "gemini-2.5-pro") {
          const err = new Error("auth_unavailable: Bearer top_secret_token_999 invalid");
          err.upstreamStatus = 401;
          throw err;
        }
        return {
          choices: [{ message: { content: makeTriageJson() } }],
          usage: { prompt_tokens: 800, completion_tokens: 120 }
        };
      }
    }
  });

  const first = await gw.triage({
    eventId: "evt-1",
    service: "orders-db",
    environment: "production",
    message: "Connection pool saturation detected."
  });
  assert.equal(first.model, "gpt-4.1-mini");
  assert.equal(first.fallbackUsed, true);
  assert.equal(first.stickyPromoted, true);
  assert.equal(first.attempts[0].cooldownKind, "credential_or_quota");
  assert.doesNotMatch(first.attempts[0].error.message, /top_secret_token_999/);
  assert.deepEqual(calls, ["gemini-2.5-pro", "gpt-4.1-mini"]);

  // Second request routes straight to sticky fallback without calling primary
  calls.length = 0;
  const second = await gw.triage({
    eventId: "evt-2",
    service: "orders-db",
    environment: "production",
    message: "Connection pool saturation persists."
  });
  assert.equal(second.model, "gpt-4.1-mini");
  assert.equal(second.stickyPromoted, false);
  assert.deepEqual(calls, ["gpt-4.1-mini"]);
});

test("gateway skips immediately on Retry-After > threshold and retries short Retry-After", async () => {
  const sleepCalls = [];
  const calls = [];
  const gw = createGateway({
    sleep: async (ms) => { sleepCalls.push(ms); },
    logger: () => {},
    cooldownStore: new CooldownStore({ retryAfterSkipThresholdMs: 30_000 }),
    modelChain: [
      { role: "primary", provider: "gemini", endpoint: "p1", model: "gemini-2.5-pro", tier: "primary" },
      { role: "fallback", provider: "openai", endpoint: "p2", model: "gpt-4.1-mini", tier: "standard" }
    ],
    transport: {
      async complete(candidate, _payload, ctx) {
        calls.push(`${candidate.model}#${ctx.attempt}`);
        if (candidate.model === "gemini-2.5-pro") {
          const err = new Error("Rate limit reached");
          err.upstreamStatus = 429;
          err.retryAfter = "75"; // > 30s threshold -> immediate skip
          throw err;
        }
        return {
          choices: [{ message: { content: makeTriageJson() } }],
          usage: { prompt_tokens: 500, completion_tokens: 80 }
        };
      }
    }
  });

  const res = await gw.triage({ message: "Pool saturation warning" });
  assert.equal(res.model, "gpt-4.1-mini");
  assert.deepEqual(calls, ["gemini-2.5-pro#1", "gpt-4.1-mini#1"]);
  assert.equal(sleepCalls.length, 0);
  assert.equal(res.attempts[0].skipToFallback, true);
  assert.equal(res.attempts[0].retryAfterMs, 75_000);

  // Now test short Retry-After (<= 30s) -> retries same route once and succeeds
  calls.length = 0;
  sleepCalls.length = 0;
  let primaryTry = 0;
  const shortRetryGw = createGateway({
    sleep: async (ms) => { sleepCalls.push(ms); },
    logger: () => {},
    cooldownStore: new CooldownStore({ retryAfterSkipThresholdMs: 30_000 }),
    modelChain: [
      { role: "primary", provider: "gemini", endpoint: "p1", model: "gemini-2.5-pro", tier: "primary" },
      { role: "fallback", provider: "openai", endpoint: "p2", model: "gpt-4.1-mini", tier: "standard" }
    ],
    transport: {
      async complete(candidate) {
        calls.push(candidate.model);
        primaryTry += 1;
        if (primaryTry === 1) {
          const err = new Error("Rate limit momentary burst");
          err.upstreamStatus = 429;
          err.retryAfter = "2"; // 2s <= 30s threshold
          throw err;
        }
        return {
          choices: [{ message: { content: makeTriageJson() } }],
          usage: { prompt_tokens: 400, completion_tokens: 60 }
        };
      }
    }
  });

  const recovered = await shortRetryGw.triage({ message: "Pool saturation burst" });
  assert.equal(recovered.model, "gemini-2.5-pro");
  assert.equal(recovered.fallbackUsed, false);
  assert.deepEqual(sleepCalls, [2_000]);
  assert.deepEqual(calls, ["gemini-2.5-pro", "gemini-2.5-pro"]);
});

test("gateway blocks unsafe/destructive model output without cooling route and falls back safely", async () => {
  const gw = createGateway({
    logger: () => {},
    stickyFallback: false,
    modelChain: [
      { role: "primary", provider: "gemini", endpoint: "p1", model: "gemini-2.5-pro", tier: "primary" },
      { role: "fallback", provider: "openai", endpoint: "p2", model: "gpt-4.1-mini", tier: "standard" }
    ],
    transport: {
      async complete(candidate) {
        if (candidate.model === "gemini-2.5-pro") {
          return {
            choices: [{
              message: {
                content: makeTriageJson({ recommendedAction: "drop_database" })
              }
            }],
            usage: { prompt_tokens: 400, completion_tokens: 50 }
          };
        }
        return {
          choices: [{ message: { content: makeTriageJson() } }],
          usage: { prompt_tokens: 400, completion_tokens: 80 }
        };
      }
    }
  });

  const res = await gw.triage({ message: "Connection pool alert" });
  assert.equal(res.model, "gpt-4.1-mini");
  assert.equal(res.attempts[0].error.code, "DESTRUCTIVE_ACTION_BLOCKED");
  assert.equal(gw.cooldownStore.isCoolingDown({ provider: "gemini", endpoint: "p1", model: "gemini-2.5-pro" }), false);
});

test("gateway triggers automatic economy downgrade after crossing costSafetyLimitUsd", async () => {
  const costGuard = new CostGuard({
    costSafetyLimitUsd: 0.005,
    economyModel: "gpt-4.1-nano"
  });
  const usedModels = [];
  const gw = createGateway({
    logger: () => {},
    costGuard,
    modelChain: [
      { role: "primary", provider: "gemini", endpoint: "p1", model: "gemini-2.5-pro", tier: "primary" },
      { role: "economy", provider: "openai", endpoint: "p3", model: "gpt-4.1-nano", tier: "economy" }
    ],
    transport: {
      async complete(candidate) {
        usedModels.push(candidate.model);
        return {
          choices: [{ message: { content: makeTriageJson() } }],
          usage: { prompt_tokens: 3_000, completion_tokens: 500 } // ~$0.00875 on pro
        };
      }
    }
  });

  const first = await gw.triage({ message: "First event" });
  assert.equal(first.model, "gemini-2.5-pro");
  assert.equal(first.downgradedToEconomy, true);

  const second = await gw.triage({ message: "Second event" });
  assert.equal(second.model, "gpt-4.1-nano");
  assert.equal(second.tier, "economy");
  assert.deepEqual(usedModels, ["gemini-2.5-pro", "gpt-4.1-nano"]);
});

test("HTTP server enforces 32 KiB limit, single-flight /health?probe=1, secret redaction, and structured logs", async () => {
  let probeCompletions = 0;
  const logEntries = [];
  const gw = createGateway({
    port: 0,
    allowedOrigins: ["http://localhost:3000"],
    logger: (entry) => logEntries.push(entry),
    modelChain: [
      { role: "primary", provider: "gemini", endpoint: "p1", model: "gemini-2.5-pro", tier: "primary" },
      { role: "economy", provider: "openai", endpoint: "p3", model: "gpt-4.1-nano", tier: "economy" }
    ],
    transport: {
      async listModels(_ep, candidates) {
        return { ok: true, models: new Set(candidates.map((c) => c.model)) };
      },
      async complete(_candidate, payload) {
        const isProbe = payload.messages?.[1]?.content === "OK";
        if (isProbe) {
          probeCompletions += 1;
          await new Promise((resolve) => setTimeout(resolve, 25));
          return { choices: [{ message: { content: "OK" } }] };
        }
        return {
          choices: [{ message: { content: makeTriageJson() } }],
          usage: { prompt_tokens: 500, completion_tokens: 80 }
        };
      }
    }
  });

  const addr = await gw.start(0, "127.0.0.1");
  const baseUrl = `http://${addr.address}:${addr.port}`;

  try {
    // 1. Concurrent GET /health?probe=1 shares single in-flight probe
    const probeResponses = await Promise.all(
      Array.from({ length: 5 }, () => fetch(`${baseUrl}/health?probe=1`).then((r) => r.json()))
    );
    assert.equal(probeCompletions, 1);
    assert.ok(probeResponses.every((item) => item.ok && item.status === "ready"));

    // 2. Valid POST /triage
    const triageRes = await fetch(`${baseUrl}/triage`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "http://localhost:3000" },
      body: JSON.stringify({
        eventId: "evt-http-1",
        service: "billing-db",
        environment: "production",
        message: "Connection pool saturation observed."
      })
    });
    assert.equal(triageRes.status, 200);
    assert.equal(triageRes.headers.get("access-control-allow-origin"), "http://localhost:3000");
    const triageBody = await triageRes.json();
    assert.equal(triageBody.ok, true);
    assert.equal(triageBody.triage.incidentType, "connection_exhaustion");

    // 3. Disallowed Origin returns 403
    const forbiddenRes = await fetch(`${baseUrl}/health`, {
      headers: { Origin: "https://untrusted.example" }
    });
    assert.equal(forbiddenRes.status, 403);

    // 4. > 32 KiB payload returns 413
    const oversized = JSON.stringify({
      message: "x".repeat(MAX_REQUEST_BODY_BYTES + 256)
    });
    const tooLargeRes = await fetch(`${baseUrl}/triage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: oversized
    });
    assert.equal(tooLargeRes.status, 413);

    // 5. Malformed JSON returns 400
    const malformedRes = await fetch(`${baseUrl}/triage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{bad-json"
    });
    assert.equal(malformedRes.status, 400);

    // 6. GET /budget works
    const budgetRes = await fetch(`${baseUrl}/budget`);
    assert.equal(budgetRes.status, 200);
    const budgetBody = await budgetRes.json();
    assert.equal(budgetBody.ok, true);
    assert.equal(budgetBody.budget.requestCount, 1);

    // 7. Structured latency logs captured
    assert.ok(logEntries.some((entry) => entry.path === "/triage" && entry.status === 200 && typeof entry.elapsedMs === "number"));

    // 8. Unknown route returns 404 and OPTIONS returns 204
    const notFoundRes = await fetch(`${baseUrl}/nonexistent`);
    assert.equal(notFoundRes.status, 404);
    const optionsRes = await fetch(`${baseUrl}/triage`, {
      method: "OPTIONS",
      headers: { Origin: "http://localhost:3000" }
    });
    assert.equal(optionsRes.status, 204);
  } finally {
    await gw.stop();
  }
});

test("GET /health?refresh=1 clears cooldown and sticky fallback promotion", async () => {
  let failPrimary = true;
  const gw = createGateway({
    port: 0,
    logger: () => {},
    modelChain: [
      { role: "primary", provider: "gemini", endpoint: "p1", model: "gemini-2.5-pro", tier: "primary" },
      { role: "fallback", provider: "openai", endpoint: "p2", model: "gpt-4.1-mini", tier: "standard" }
    ],
    transport: {
      async listModels(_ep, candidates) {
        return { ok: true, models: new Set(candidates.map((c) => c.model)) };
      },
      async complete(candidate, payload) {
        if (payload.messages?.[1]?.content === "OK") {
          return { choices: [{ message: { content: "OK" } }] };
        }
        if (candidate.model === "gemini-2.5-pro" && failPrimary) {
          const err = new Error("Upstream 503");
          err.upstreamStatus = 503;
          throw err;
        }
        return {
          choices: [{ message: { content: makeTriageJson() } }],
          usage: { prompt_tokens: 300, completion_tokens: 60 }
        };
      }
    }
  });

  await gw.triage({ message: "Pool saturation" });
  assert.equal(gw.getStickyCandidateKey(), "openai:p2:gpt-4.1-mini");

  failPrimary = false;
  const refreshed = await gw.healthSnapshot({ refresh: true, probeModels: true });
  assert.equal(refreshed.status, "ready");
  assert.equal(refreshed.stickyActive, false);
  assert.equal(refreshed.primaryReady, true);
});

test("HTTP POST /triage returns 502 with redacted error attempts when all MODEL_CHAIN routes fail", async () => {
  const gw = createGateway({
    port: 0,
    logger: () => {},
    modelChain: [
      { role: "primary", provider: "gemini", endpoint: "p1", model: "gemini-2.5-pro", tier: "primary" }
    ],
    transport: {
      async listModels(_ep, candidates) {
        return { ok: true, models: new Set(candidates.map((c) => c.model)) };
      },
      async complete() {
        const err = new Error("Auth failed with Bearer live_secret_abc123");
        err.upstreamStatus = 401;
        throw err;
      }
    }
  });

  const addr = await gw.start(0, "127.0.0.1");
  try {
    const res = await fetch(`http://${addr.address}:${addr.port}/triage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: "Database timeout" })
    });
    assert.equal(res.status, 502);
    const body = await res.json();
    assert.equal(body.ok, false);
    assert.equal(body.attempts.length, 1);
    assert.doesNotMatch(JSON.stringify(body), /live_secret_abc123/);
    assert.match(body.attempts[0].error.message, /Bearer <redacted>/);
  } finally {
    await gw.stop();
  }
});

test("HTTP gateway rejects non-loopback Host (DNS rebinding), rejects malformed targets with 400, and supports built-in mock mode", async () => {
  const gw = createGateway({
    port: 0,
    mockMode: true,
    logger: () => {}
  });

  const addr = await gw.start(0, "127.0.0.1");
  const baseUrl = `http://${addr.address}:${addr.port}`;

  try {
    // 1. DNS rebinding protection via Host header allowlist
    const net = await import("node:net");
    const evilHostResponse = await new Promise((resolve, reject) => {
      const sock = net.createConnection({ host: addr.address, port: addr.port }, () => {
        sock.write("GET /health HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n");
      });
      let raw = "";
      sock.on("data", (chunk) => { raw += chunk.toString("utf8"); });
      sock.on("end", () => resolve(raw));
      sock.on("error", reject);
    });
    assert.match(evilHostResponse, /^HTTP\/1\.1 403 /);
    assert.match(evilHostResponse, /Host not allowed/);

    // 2. Malformed URL target returns 400 instead of unhandled 500
    const badUrlResponse = await new Promise((resolve, reject) => {
      const sock = net.createConnection({ host: addr.address, port: addr.port }, () => {
        sock.write(`GET /triage\\bad HTTP/1.1\r\nHost: 127.0.0.1:${addr.port}\r\nConnection: close\r\n\r\n`);
      });
      let raw = "";
      sock.on("data", (chunk) => { raw += chunk.toString("utf8"); });
      sock.on("end", () => resolve(raw));
      sock.on("error", reject);
    });
    assert.match(badUrlResponse, /^HTTP\/1\.1 400 /);
    assert.match(badUrlResponse, /Malformed request target/);

    // 3. Built-in --mock mode responds to preflight probe and /triage end-to-end
    const healthRes = await fetch(`${baseUrl}/health?probe=1`);
    assert.equal(healthRes.status, 200);
    const healthBody = await healthRes.json();
    assert.equal(healthBody.status, "ready");

    const triageRes = await fetch(`${baseUrl}/triage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        eventId: "evt-mock-1",
        service: "orders-postgres",
        environment: "production",
        message: "Primary WAL disk at 99% exhaustion"
      })
    });
    assert.equal(triageRes.status, 200);
    const triageBody = await triageRes.json();
    assert.equal(triageBody.triage.severity, "P1");
    assert.equal(triageBody.triage.incidentType, "disk_saturation");
  } finally {
    await gw.stop();
  }
});
