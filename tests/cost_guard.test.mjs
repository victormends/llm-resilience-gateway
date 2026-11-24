import test from "node:test";
import assert from "node:assert/strict";

import { BudgetLimitError, CostGuard, extractTokenUsage } from "../src/cost_guard.mjs";

test("extractTokenUsage normalizes OpenAI and Anthropic token usage and clamps cached tokens", () => {
  assert.deepEqual(
    extractTokenUsage({
      prompt_tokens: 1_000,
      completion_tokens: 250,
      prompt_tokens_details: { cached_tokens: 400 }
    }),
    {
      promptTokens: 1_000,
      cachedTokens: 400,
      uncachedPromptTokens: 600,
      completionTokens: 250
    }
  );

  assert.deepEqual(
    extractTokenUsage({
      input_tokens: 500,
      cache_read_input_tokens: 900, // should clamp to promptTokens
      output_tokens: -10
    }),
    {
      promptTokens: 500,
      cachedTokens: 500,
      uncachedPromptTokens: 0,
      completionTokens: 0
    }
  );
});

test("CostGuard tracks cached vs uncached USD spend and trips auto-downgrade to economy tier", () => {
  let clock = 5_000;
  const guard = new CostGuard({
    costSafetyLimitUsd: 0.01,
    economyModel: "gpt-4.1-nano",
    now: () => clock
  });

  const chain = [
    { role: "primary", model: "gemini-2.5-pro", tier: "primary" },
    { role: "fallback_standard", model: "gpt-4.1-mini", tier: "standard" },
    { role: "fallback_economy", model: "gpt-4.1-nano", tier: "economy" }
  ];

  // Before threshold: full chain intact
  assert.equal(guard.selectCandidates(chain).length, 3);

  // gemini-2.5-pro: cached 0.3125/1M, uncached 1.25/1M, output 10.00/1M
  // 2000 cached ($0.000625) + 2000 uncached ($0.0025) + 500 output ($0.005) = $0.008125
  const first = guard.recordUsage("gemini-2.5-pro", {
    prompt_tokens: 4_000,
    completion_tokens: 500,
    prompt_tokens_details: { cached_tokens: 2_000 }
  });
  assert.equal(first.callCostUsd, 0.008125);
  assert.equal(first.downgradeActive, false);
  assert.equal(first.justDowngraded, false);

  // Second call crosses $0.01 limit -> triggers economy downgrade
  clock += 1_000;
  const second = guard.recordUsage("gemini-2.5-pro", {
    prompt_tokens: 2_000,
    completion_tokens: 300,
    prompt_tokens_details: { cached_tokens: 0 }
  });
  assert.equal(second.downgradeActive, true);
  assert.equal(second.justDowngraded, true);
  assert.ok(second.totalEstimatedCostUsd >= 0.01);

  // selectCandidates now restricts routing to economy tier
  const downgradedChain = guard.selectCandidates(chain);
  assert.deepEqual(downgradedChain.map((c) => c.model), ["gpt-4.1-nano"]);

  const summary = guard.summary();
  assert.equal(summary.requestCount, 2);
  assert.equal(summary.totalPromptTokens, 6_000);
  assert.equal(summary.totalCachedTokens, 2_000);
  assert.equal(summary.totalUncachedPromptTokens, 4_000);
  assert.equal(summary.totalCompletionTokens, 800);
  assert.equal(summary.downgradeTransitions, 1);
  assert.equal(summary.byModel.length, 1);
});

test("CostGuard enforces optional hardStopLimitUsd and resets cleanly", () => {
  const guard = new CostGuard({
    costSafetyLimitUsd: 0.005,
    hardStopLimitUsd: 0.015,
    economyModel: "gpt-4.1-nano"
  });

  guard.assertWithinHardLimit();
  guard.recordUsage("gemini-2.5-pro", { prompt_tokens: 4_000, completion_tokens: 1_500 });
  assert.equal(guard.hardStopped, true);

  assert.throws(
    () => guard.assertWithinHardLimit(),
    (error) => error instanceof BudgetLimitError
      && error.code === "BUDGET_HARD_LIMIT_EXCEEDED"
      && error.statusCode === 429
  );

  guard.reset();
  assert.equal(guard.totalEstimatedCostUsd, 0);
  assert.equal(guard.downgradeActive, false);
  assert.equal(guard.hardStopped, false);
  guard.assertWithinHardLimit();
});

test("CostGuard selectCandidates falls back to lowest-cost model when no tier=economy tag is present", () => {
  const guard = new CostGuard({
    costSafetyLimitUsd: 0.001,
    economyModel: "custom-economy"
  });
  guard.recordUsage("gemini-2.5-pro", { prompt_tokens: 1_000, completion_tokens: 200 });
  assert.equal(guard.downgradeActive, true);

  const untagged = [
    { model: "gemini-2.5-pro" },
    { model: "gpt-4.1-nano" },
    { model: "gpt-4.1-mini" }
  ];
  const sorted = guard.selectCandidates(untagged);
  assert.equal(sorted[0].model, "gpt-4.1-nano");
});

test("CostGuard supports custom pricingTable, candidate pricing overrides, and Infinity limit", () => {
  const guard = new CostGuard({
    costSafetyLimitUsd: Infinity,
    pricingTable: {
      "custom-model": { inputPer1M: 2.0, cachedInputPer1M: 0.5, outputPer1M: 8.0 }
    }
  });

  const first = guard.recordUsage("custom-model", {
    prompt_tokens: 1_000_000,
    completion_tokens: 500_000,
    prompt_tokens_details: { cached_tokens: 500_000 }
  });
  // 500k * 0.5/1M ($0.25) + 500k * 2.0/1M ($1.00) + 500k * 8.0/1M ($4.00) = $5.25
  assert.equal(first.callCostUsd, 5.25);
  assert.equal(first.downgradeActive, false);

  const override = guard.estimateCallCost(
    "custom-model",
    { prompt_tokens: 1_000_000, completion_tokens: 0 },
    { inputPer1M: 0.25, cachedInputPer1M: 0.05, outputPer1M: 1.0 }
  );
  assert.equal(override.callCostUsd, 0.25);
});

test("CostGuard ignores malformed or NaN token fields without corrupting ledger", () => {
  const guard = new CostGuard({ costSafetyLimitUsd: 0.5 });
  const record = guard.recordUsage("gpt-4.1-mini", {
    prompt_tokens: "not-a-number",
    completion_tokens: NaN,
    prompt_tokens_details: { cached_tokens: -50 }
  });
  assert.equal(record.promptTokens, 0);
  assert.equal(record.cachedTokens, 0);
  assert.equal(record.completionTokens, 0);
  assert.equal(record.callCostUsd, 0);
  assert.equal(guard.summary().cacheHitRate, 0);
});
