import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { runBenchmark } from "../eval/run_benchmark.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("offline resilience benchmark improves post-guardrail accuracy and keeps zero unsafe leaks", async () => {
  const report = await runBenchmark({ repeats: 3, concurrency: 4, seed: 20261124 });
  const { metrics } = report;

  assert.equal(metrics.totalRequests, 36);
  assert.equal(metrics.successfulRequests, 36);
  assert.equal(metrics.failedRequests, 0);
  assert.ok(
    metrics.postGuardrailAccuracy > metrics.rawAccuracy,
    `Expected postGuardrailAccuracy (${metrics.postGuardrailAccuracy}) > rawAccuracy (${metrics.rawAccuracy})`
  );
  assert.equal(metrics.postGuardrailAccuracy, 1);
  assert.equal(metrics.stabilityRate, 1);
  assert.ok(metrics.medianLatencyMs > 0);
  assert.ok(metrics.p95LatencyMs >= metrics.medianLatencyMs);
  assert.ok(metrics.resilience.destructiveAttemptsBlocked > 0);
  assert.equal(metrics.resilience.unsafeLeakCount, 0);
  assert.ok(metrics.resilience.cooldownSkips > 0);
  assert.ok(metrics.resilience.fallbackCount > 0);
  assert.equal(metrics.budget.downgradeActive, true);
  assert.ok(metrics.resilience.economyRoutedCount > 0);
});

test("offline benchmark is reproducible for a given deterministic seed", async () => {
  const first = await runBenchmark({ repeats: 3, concurrency: 1, seed: 4242 });
  const second = await runBenchmark({ repeats: 3, concurrency: 1, seed: 4242 });

  assert.equal(first.metrics.rawAccuracy, second.metrics.rawAccuracy);
  assert.equal(first.metrics.postGuardrailAccuracy, second.metrics.postGuardrailAccuracy);
  assert.equal(first.metrics.stabilityRate, second.metrics.stabilityRate);
  assert.equal(first.metrics.budget.totalEstimatedCostUsd, second.metrics.budget.totalEstimatedCostUsd);
  assert.deepEqual(first.metrics.resilience, second.metrics.resilience);
});

test("repository remains free of domain leaks, operator names, and workstation paths", async () => {
  const decode = (b64) => Buffer.from(b64, "base64").toString("utf8");
  const forbiddenPatterns = [
    new RegExp(decode("cG9ja2V0XHMqZm0="), "i"),
    new RegExp(decode("Y21zXC5wb2NrZXRmbQ=="), "i"),
    new RegExp(decode("Y2hyb21lLWV4dGVuc2lvbg=="), "i"),
    new RegExp(decode("bGlua2VkaW4tc2Nhbm5lcg=="), "i"),
    new RegExp(decode("XGJtb25lc3RcYg=="), "i"),
    new RegExp(decode("XGJwZWRyb3NvXGI="), "i"),
    new RegExp(decode("XGJiZWx2b1xi"), "i"),
    new RegExp(decode("XGJnaW9yZ2lhXGI="), "i"),
    new RegExp(decode("XGJoaWdvclxi"), "i"),
    new RegExp(decode("XGJqb2ppXGI="), "i"),
    new RegExp(decode("QzpcXFVzZXJzXFxqdmljdA=="), "i")
  ];

  const filesToScan = [
    "package.json",
    "README.md",
    "LICENSE",
    ".gitignore",
    ".github/workflows/ci.yml",
    "src/cooldown.mjs",
    "src/cost_guard.mjs",
    "src/guardrails.mjs",
    "src/gateway.mjs",
    "eval/run_benchmark.mjs",
    "tests/cooldown.test.mjs",
    "tests/cost_guard.test.mjs",
    "tests/guardrails.test.mjs",
    "tests/gateway.test.mjs",
    "tests/eval_harness.test.mjs"
  ];

  for (const relPath of filesToScan) {
    const content = await fs.readFile(path.join(repoRoot, relPath), "utf8");
    for (const pattern of forbiddenPatterns) {
      assert.equal(
        pattern.test(content),
        false,
        `Forbidden pattern ${pattern} matched in ${relPath}`
      );
    }
  }
});
