import { redactSecrets } from "./guardrails.mjs";

export const DEFAULT_CREDENTIAL_COOLDOWN_MS = 6 * 60 * 60_000;
export const DEFAULT_TRANSIENT_COOLDOWN_MS = 15 * 60_000;
export const DEFAULT_RETRY_AFTER_SKIP_THRESHOLD_MS = 30_000;

const AUTH_HARD_FAILURE_RE = /auth_unavailable|no auth available|authentication (?:failed|required)|invalid credentials?|credentials? (?:expired|invalid)|validation_required|verify your account|permission_denied|token.{0,24}(?:expired|invalid)|(?:expired|invalid).{0,24}token/i;
const QUOTA_OR_RATE_RE = /quota|rate[ _-]?limit|resource[ _-]?exhausted|too many requests|insufficient (?:credits?|quota)/i;
const TRANSIENT_NETWORK_RE = /ECONNREFUSED|ECONNRESET|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|socket hang up|temporarily unavailable|upstream timeout/i;

/**
 * Generates a stable route identifier for a candidate model entry.
 * @param {{ provider?: string, endpoint?: string, proxy?: string, model: string }} candidate
 * @returns {string}
 */
export function routeKey(candidate) {
  const provider = String(candidate?.provider || "default").trim();
  const route = String(candidate?.endpoint || candidate?.proxy || "direct").trim();
  const model = String(candidate?.model || "unknown").trim();
  return `${provider}:${route}:${model}`;
}

/**
 * Parses an HTTP Retry-After value (numeric seconds or HTTP-date) into milliseconds.
 * Returns null if the value is absent or invalid.
 * @param {unknown} rawValue
 * @param {number} [nowMs=Date.now()]
 * @returns {number | null}
 */
export function parseRetryAfterMs(rawValue, nowMs = Date.now()) {
  if (rawValue === undefined || rawValue === null) return null;
  if (typeof rawValue === "number") {
    return Number.isFinite(rawValue) && rawValue >= 0 ? Math.round(rawValue) : null;
  }
  const text = String(rawValue).trim();
  if (!text) return null;

  if (/^\d+(?:\.\d+)?$/.test(text)) {
    const seconds = Number(text);
    return Number.isFinite(seconds) && seconds >= 0 ? Math.round(seconds * 1000) : null;
  }

  const targetTimestamp = Date.parse(text);
  if (Number.isFinite(targetTimestamp)) {
    return Math.max(0, targetTimestamp - nowMs);
  }
  return null;
}

function extractRetryAfterMs(error, nowMs) {
  if (!error || typeof error !== "object") return null;
  if (typeof error.retryAfterMs === "number" && Number.isFinite(error.retryAfterMs) && error.retryAfterMs >= 0) {
    return Math.round(error.retryAfterMs);
  }
  const headerLookup = typeof error.headers?.get === "function"
    ? error.headers.get("retry-after")
    : error.headers?.["retry-after"] ?? error.headers?.["Retry-After"];
  const raw = error.retryAfter ?? headerLookup;
  return parseRetryAfterMs(raw, nowMs);
}

/**
 * Classifies an upstream error semantically into credential/quota vs transient
 * cooldown policies and computes Retry-After skip decisions.
 *
 * @param {unknown} error
 * @param {{
 *   forceTransient?: boolean,
 *   credentialCooldownMs?: number,
 *   transientCooldownMs?: number,
 *   retryAfterSkipThresholdMs?: number,
 *   nowMs?: number
 * }} [options]
 */
export function classifyFailure(error, options = {}) {
  const credentialCooldownMs = Math.max(1_000, Number(options.credentialCooldownMs ?? DEFAULT_CREDENTIAL_COOLDOWN_MS));
  const transientCooldownMs = Math.max(1_000, Number(options.transientCooldownMs ?? DEFAULT_TRANSIENT_COOLDOWN_MS));
  const retryAfterSkipThresholdMs = Math.max(0, Number(options.retryAfterSkipThresholdMs ?? DEFAULT_RETRY_AFTER_SKIP_THRESHOLD_MS));
  const nowMs = Number(options.nowMs ?? Date.now());

  const status = Number(error?.upstreamStatus || error?.statusCode || error?.status) || 0;
  const message = String(error?.message || "");
  const retryAfterMs = extractRetryAfterMs(error, nowMs);
  const exceedsThreshold = retryAfterMs !== null && retryAfterMs > retryAfterSkipThresholdMs;

  const isAuthHardFailure = status === 401 || status === 403 || AUTH_HARD_FAILURE_RE.test(message);
  const isQuotaOrRateLimit = status === 429 || QUOTA_OR_RATE_RE.test(message);

  if (isAuthHardFailure) {
    return {
      kind: "credential_or_quota",
      status: status || null,
      durationMs: Math.max(credentialCooldownMs, retryAfterMs || 0),
      retryAfterMs,
      skipToFallback: true,
      shouldRetrySameRoute: false,
      retryDelayMs: null,
      reason: "auth_or_permission_failure"
    };
  }

  if (isQuotaOrRateLimit) {
    const canShortRetry = retryAfterMs !== null && !exceedsThreshold;
    return {
      kind: "credential_or_quota",
      status: status || null,
      durationMs: Math.max(credentialCooldownMs, retryAfterMs || 0),
      retryAfterMs,
      skipToFallback: !canShortRetry,
      shouldRetrySameRoute: canShortRetry,
      retryDelayMs: canShortRetry ? retryAfterMs : null,
      reason: exceedsThreshold ? "retry_after_exceeds_threshold" : "rate_limit_or_quota"
    };
  }

  const isTimeout = error?.name === "AbortError"
    || error?.name === "TimeoutError"
    || status === 408
    || status === 504;
  const isTransientStatus = [408, 502, 503, 504].includes(status) || status >= 500;
  const isTransientSignal = isTimeout
    || isTransientStatus
    || TRANSIENT_NETWORK_RE.test(message)
    || TRANSIENT_NETWORK_RE.test(String(error?.code || ""))
    || Boolean(options.forceTransient);

  if (isTransientSignal) {
    return {
      kind: "transient",
      status: status || null,
      durationMs: Math.max(transientCooldownMs, retryAfterMs || 0),
      retryAfterMs,
      skipToFallback: exceedsThreshold,
      shouldRetrySameRoute: !exceedsThreshold,
      retryDelayMs: !exceedsThreshold ? retryAfterMs : null,
      reason: exceedsThreshold ? "retry_after_exceeds_threshold" : (isTimeout ? "upstream_timeout" : "transient_upstream_error")
    };
  }

  return {
    kind: null,
    status: status || null,
    durationMs: 0,
    retryAfterMs,
    skipToFallback: true,
    shouldRetrySameRoute: false,
    retryDelayMs: null,
    reason: "non_cooldown_error"
  };
}

/**
 * In-memory per-route circuit breaker and semantic cooldown store.
 */
export class CooldownStore {
  /**
   * @param {{
   *   credentialCooldownMs?: number,
   *   transientCooldownMs?: number,
   *   retryAfterSkipThresholdMs?: number,
   *   now?: () => number
   * }} [options]
   */
  constructor(options = {}) {
    this.credentialCooldownMs = Math.max(1_000, Number(options.credentialCooldownMs ?? DEFAULT_CREDENTIAL_COOLDOWN_MS));
    this.transientCooldownMs = Math.max(1_000, Number(options.transientCooldownMs ?? DEFAULT_TRANSIENT_COOLDOWN_MS));
    this.retryAfterSkipThresholdMs = Math.max(0, Number(options.retryAfterSkipThresholdMs ?? DEFAULT_RETRY_AFTER_SKIP_THRESHOLD_MS));
    this.now = typeof options.now === "function" ? options.now : () => Date.now();
    this._states = new Map();
  }

  /**
   * @param {unknown} error
   * @param {boolean} [forceTransient=false]
   */
  classify(error, forceTransient = false) {
    return classifyFailure(error, {
      forceTransient,
      credentialCooldownMs: this.credentialCooldownMs,
      transientCooldownMs: this.transientCooldownMs,
      retryAfterSkipThresholdMs: this.retryAfterSkipThresholdMs,
      nowMs: this.now()
    });
  }

  /**
   * @param {{ provider?: string, endpoint?: string, proxy?: string, model: string }} candidate
   */
  getState(candidate) {
    return this._states.get(routeKey(candidate)) || null;
  }

  /**
   * @param {{ provider?: string, endpoint?: string, proxy?: string, model: string }} candidate
   */
  remainingMs(candidate) {
    const state = this.getState(candidate);
    if (!state) return 0;
    return Math.max(0, Number(state.cooldownUntil || 0) - this.now());
  }

  /**
   * @param {{ provider?: string, endpoint?: string, proxy?: string, model: string }} candidate
   */
  isCoolingDown(candidate) {
    return this.remainingMs(candidate) > 0;
  }

  /**
   * @param {{ provider?: string, endpoint?: string, proxy?: string, model: string }} candidate
   * @param {number} [elapsedMs=0]
   * @param {number} [requestStartedAt]
   */
  markReady(candidate, elapsedMs = 0, requestStartedAt = undefined) {
    const key = routeKey(candidate);
    const existing = this._states.get(key);
    if (
      requestStartedAt !== undefined
      && existing?.status === "unavailable"
      && Number(existing.checkedAt || 0) > requestStartedAt
    ) {
      return existing;
    }
    const checkedAt = this.now();
    const state = {
      key,
      status: "ready",
      checkedAt,
      elapsedMs: Math.max(0, Math.round(elapsedMs || 0)),
      cooldownUntil: 0,
      cooldownKind: null,
      reason: null,
      error: null
    };
    this._states.set(state.key, state);
    return state;
  }

  /**
   * @param {{ provider?: string, endpoint?: string, proxy?: string, model: string }} candidate
   * @param {unknown} error
   * @param {number} [elapsedMs=0]
   * @param {boolean} [forceTransient=false]
   */
  markUnavailable(candidate, error, elapsedMs = 0, forceTransient = false) {
    const checkedAt = this.now();
    const classification = this.classify(error, forceTransient);
    const status = Number(error?.upstreamStatus || error?.statusCode || error?.status) || null;
    const state = {
      key: routeKey(candidate),
      status: "unavailable",
      checkedAt,
      elapsedMs: Math.max(0, Math.round(elapsedMs || 0)),
      cooldownUntil: classification.durationMs > 0 ? checkedAt + classification.durationMs : 0,
      cooldownKind: classification.kind,
      reason: classification.reason,
      error: {
        status,
        message: redactSecrets(error?.message || "Unknown upstream error.")
      }
    };
    this._states.set(state.key, state);
    return { classification, state };
  }

  /**
   * @param {{ provider?: string, endpoint?: string, proxy?: string, model: string }} [candidate]
   */
  reset(candidate) {
    if (candidate) {
      this._states.delete(routeKey(candidate));
      return;
    }
    this._states.clear();
  }

  snapshot() {
    return [...this._states.values()].map((state) => ({
      ...state,
      cooldownRemainingMs: Math.max(0, Number(state.cooldownUntil || 0) - this.now())
    }));
  }
}
