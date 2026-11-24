export const DEFAULT_COST_SAFETY_LIMIT_USD = 0.35;

export const DEFAULT_PRICING_TABLE = Object.freeze({
  "gemini-2.5-pro": Object.freeze({ inputPer1M: 1.25, cachedInputPer1M: 0.3125, outputPer1M: 10.0 }),
  "gemini-2.5-flash": Object.freeze({ inputPer1M: 0.3, cachedInputPer1M: 0.075, outputPer1M: 2.5 }),
  "gpt-4.1-mini": Object.freeze({ inputPer1M: 0.4, cachedInputPer1M: 0.1, outputPer1M: 1.6 }),
  "gpt-4.1-nano": Object.freeze({ inputPer1M: 0.1, cachedInputPer1M: 0.025, outputPer1M: 0.4 }),
  "claude-3-5-haiku": Object.freeze({ inputPer1M: 0.8, cachedInputPer1M: 0.08, outputPer1M: 4.0 }),
  "tier-primary": Object.freeze({ inputPer1M: 1.25, cachedInputPer1M: 0.3125, outputPer1M: 10.0 }),
  "tier-standard": Object.freeze({ inputPer1M: 0.4, cachedInputPer1M: 0.1, outputPer1M: 1.6 }),
  "tier-economy": Object.freeze({ inputPer1M: 0.1, cachedInputPer1M: 0.025, outputPer1M: 0.4 })
});

export class BudgetLimitError extends Error {
  /**
   * @param {string} message
   * @param {{ code?: string, statusCode?: number, totalEstimatedCostUsd?: number, limitUsd?: number }} [meta]
   */
  constructor(message, meta = {}) {
    super(message);
    this.name = "BudgetLimitError";
    this.code = meta.code || "BUDGET_HARD_LIMIT_EXCEEDED";
    this.statusCode = Number(meta.statusCode) || 429;
    this.totalEstimatedCostUsd = meta.totalEstimatedCostUsd ?? 0;
    this.limitUsd = meta.limitUsd ?? 0;
  }
}

function nonNegativeInt(value) {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) return 0;
  return Math.floor(num);
}

/**
 * Normalizes token usage payloads from OpenAI, Gemini-compat, or Anthropic-style responses.
 * @param {Record<string, any> | null | undefined} usage
 */
export function extractTokenUsage(usage) {
  if (!usage || typeof usage !== "object") {
    return {
      promptTokens: 0,
      cachedTokens: 0,
      uncachedPromptTokens: 0,
      completionTokens: 0
    };
  }
  const promptTokens = nonNegativeInt(
    usage.promptTokens ?? usage.prompt_tokens ?? usage.input_tokens ?? 0
  );
  const rawCached = nonNegativeInt(
    usage.cachedTokens
    ?? usage.prompt_tokens_details?.cached_tokens
    ?? usage.input_tokens_details?.cached_tokens
    ?? usage.cache_read_input_tokens
    ?? 0
  );
  const cachedTokens = Math.min(promptTokens, rawCached);
  const uncachedPromptTokens = Math.max(0, promptTokens - cachedTokens);
  const completionTokens = nonNegativeInt(
    usage.completionTokens ?? usage.completion_tokens ?? usage.output_tokens ?? 0
  );

  return {
    promptTokens,
    cachedTokens,
    uncachedPromptTokens,
    completionTokens
  };
}

/**
 * Tracks token/cached-token USD spend across requests and trips a cost safety
 * circuit breaker that automatically downgrades routing to an economy tier.
 */
export class CostGuard {
  /**
   * @param {{
   *   costSafetyLimitUsd?: number,
   *   hardStopLimitUsd?: number | null,
   *   economyModel?: string,
   *   pricingTable?: Record<string, { inputPer1M: number, cachedInputPer1M: number, outputPer1M: number }>,
   *   now?: () => number
   * }} [options]
   */
  constructor(options = {}) {
    const rawSafetyLimit = options.costSafetyLimitUsd ?? DEFAULT_COST_SAFETY_LIMIT_USD;
    this.costSafetyLimitUsd = rawSafetyLimit === Infinity
      ? Infinity
      : Math.max(0, Number(rawSafetyLimit));
    this.hardStopLimitUsd = options.hardStopLimitUsd === undefined || options.hardStopLimitUsd === null
      ? null
      : Math.max(0, Number(options.hardStopLimitUsd));
    this.economyModel = String(options.economyModel || "gpt-4.1-nano");
    this.pricingTable = {
      ...DEFAULT_PRICING_TABLE,
      ...(options.pricingTable || {})
    };
    this.now = typeof options.now === "function" ? options.now : () => Date.now();
    this.reset();
  }

  /**
   * @param {string} modelId
   * @param {{ inputPer1M?: number, cachedInputPer1M?: number, outputPer1M?: number } | null} [explicitPricing]
   */
  resolvePricing(modelId, explicitPricing = null) {
    if (explicitPricing && typeof explicitPricing === "object") {
      return {
        inputPer1M: Math.max(0, Number(explicitPricing.inputPer1M) || 0),
        cachedInputPer1M: Math.max(0, Number(explicitPricing.cachedInputPer1M) || 0),
        outputPer1M: Math.max(0, Number(explicitPricing.outputPer1M) || 0)
      };
    }
    const key = String(modelId || "").trim();
    if (key && this.pricingTable[key]) return this.pricingTable[key];
    const lower = key.toLowerCase();
    const matchedKey = Object.keys(this.pricingTable).find((entry) => entry.toLowerCase() === lower);
    if (matchedKey) return this.pricingTable[matchedKey];
    if (/\b(?:nano|lite|economy|micro)\b/i.test(lower)) return this.pricingTable["tier-economy"];
    if (/\b(?:flash|mini|haiku|standard)\b/i.test(lower)) return this.pricingTable["tier-standard"];
    if (/\b(?:pro|sonnet|opus|primary)\b/i.test(lower)) return this.pricingTable["tier-primary"];
    return { inputPer1M: 0.5, cachedInputPer1M: 0.125, outputPer1M: 2.0 };
  }

  /**
   * @param {string} modelId
   * @param {Record<string, any> | null | undefined} usage
   * @param {{ inputPer1M?: number, cachedInputPer1M?: number, outputPer1M?: number } | null} [explicitPricing]
   */
  estimateCallCost(modelId, usage, explicitPricing = null) {
    const normalized = extractTokenUsage(usage);
    const pricing = this.resolvePricing(modelId, explicitPricing);
    const callCostUsd =
      (normalized.cachedTokens / 1_000_000) * pricing.cachedInputPer1M
      + (normalized.uncachedPromptTokens / 1_000_000) * pricing.inputPer1M
      + (normalized.completionTokens / 1_000_000) * pricing.outputPer1M;
    return {
      ...normalized,
      callCostUsd
    };
  }

  /**
   * @param {string} modelId
   * @param {Record<string, any> | null | undefined} usage
   * @param {{ inputPer1M?: number, cachedInputPer1M?: number, outputPer1M?: number } | null} [explicitPricing]
   */
  recordUsage(modelId, usage, explicitPricing = null) {
    const {
      promptTokens,
      cachedTokens,
      uncachedPromptTokens,
      completionTokens,
      callCostUsd
    } = this.estimateCallCost(modelId, usage, explicitPricing);

    this.totalPromptTokens += promptTokens;
    this.totalCachedTokens += cachedTokens;
    this.totalUncachedPromptTokens += uncachedPromptTokens;
    this.totalCompletionTokens += completionTokens;
    this.totalEstimatedCostUsd += callCostUsd;
    this.requestCount += 1;

    const bucket = this._byModel.get(modelId) || {
      model: modelId,
      requests: 0,
      promptTokens: 0,
      cachedTokens: 0,
      uncachedPromptTokens: 0,
      completionTokens: 0,
      estimatedCostUsd: 0
    };
    bucket.requests += 1;
    bucket.promptTokens += promptTokens;
    bucket.cachedTokens += cachedTokens;
    bucket.uncachedPromptTokens += uncachedPromptTokens;
    bucket.completionTokens += completionTokens;
    bucket.estimatedCostUsd += callCostUsd;
    this._byModel.set(modelId, bucket);

    const previouslyDowngraded = this.downgradeActive;
    if (
      !this.downgradeActive
      && Number.isFinite(this.costSafetyLimitUsd)
      && this.totalEstimatedCostUsd >= this.costSafetyLimitUsd
    ) {
      this.downgradeActive = true;
      this.downgradeTriggeredAt = this.now();
      this.downgradeTransitions += 1;
    }

    if (this.hardStopLimitUsd !== null && this.totalEstimatedCostUsd >= this.hardStopLimitUsd) {
      this.hardStopped = true;
    }

    return {
      model: modelId,
      promptTokens,
      cachedTokens,
      uncachedPromptTokens,
      completionTokens,
      callCostUsd: Number(callCostUsd.toFixed(8)),
      totalEstimatedCostUsd: Number(this.totalEstimatedCostUsd.toFixed(8)),
      downgradeActive: this.downgradeActive,
      justDowngraded: !previouslyDowngraded && this.downgradeActive,
      hardStopped: this.hardStopped
    };
  }

  assertWithinHardLimit() {
    if (this.hardStopLimitUsd !== null && this.totalEstimatedCostUsd >= this.hardStopLimitUsd) {
      throw new BudgetLimitError(
        `Hard cost limit exceeded ($${this.totalEstimatedCostUsd.toFixed(4)} >= $${this.hardStopLimitUsd.toFixed(4)} USD).`,
        {
          code: "BUDGET_HARD_LIMIT_EXCEEDED",
          statusCode: 429,
          totalEstimatedCostUsd: Number(this.totalEstimatedCostUsd.toFixed(6)),
          limitUsd: this.hardStopLimitUsd
        }
      );
    }
  }

  /**
   * Filters or reorders the candidate chain when the cost safety limit has tripped.
   * Prefers economy-tier models (or lowest-cost model if no tier tag is set).
   * @template {{ model: string, tier?: string, pricing?: { outputPer1M?: number } }} T
   * @param {T[]} candidates
   * @returns {T[]}
   */
  selectCandidates(candidates) {
    if (!Array.isArray(candidates) || candidates.length === 0) return [];
    if (!this.downgradeActive) return [...candidates];

    const economyMatches = candidates.filter(
      (candidate) => candidate.tier === "economy" || candidate.model === this.economyModel
    );
    if (economyMatches.length > 0) {
      return economyMatches;
    }

    return [...candidates].sort((left, right) => {
      const leftPrice = this.resolvePricing(left.model, left.pricing).outputPer1M;
      const rightPrice = this.resolvePricing(right.model, right.pricing).outputPer1M;
      return leftPrice - rightPrice;
    });
  }

  summary() {
    const cacheHitRate = this.totalPromptTokens > 0
      ? Number((this.totalCachedTokens / this.totalPromptTokens).toFixed(4))
      : 0;
    return {
      requestCount: this.requestCount,
      totalPromptTokens: this.totalPromptTokens,
      totalCachedTokens: this.totalCachedTokens,
      totalUncachedPromptTokens: this.totalUncachedPromptTokens,
      totalCompletionTokens: this.totalCompletionTokens,
      cacheHitRate,
      totalEstimatedCostUsd: Number(this.totalEstimatedCostUsd.toFixed(6)),
      costSafetyLimitUsd: this.costSafetyLimitUsd,
      hardStopLimitUsd: this.hardStopLimitUsd,
      downgradeActive: this.downgradeActive,
      downgradeTriggeredAt: this.downgradeTriggeredAt,
      downgradeTransitions: this.downgradeTransitions,
      hardStopped: this.hardStopped,
      economyModel: this.economyModel,
      byModel: [...this._byModel.values()].map((entry) => ({
        ...entry,
        estimatedCostUsd: Number(entry.estimatedCostUsd.toFixed(6))
      }))
    };
  }

  reset() {
    this.totalPromptTokens = 0;
    this.totalCachedTokens = 0;
    this.totalUncachedPromptTokens = 0;
    this.totalCompletionTokens = 0;
    this.totalEstimatedCostUsd = 0;
    this.requestCount = 0;
    this.downgradeActive = false;
    this.downgradeTriggeredAt = null;
    this.downgradeTransitions = 0;
    this.hardStopped = false;
    this._byModel = new Map();
  }
}
