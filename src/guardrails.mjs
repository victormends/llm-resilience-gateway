/**
 * Deterministic prompt-safety, strict JSON Schema validation, and incident
 * triage policy guardrails. Zero external dependencies.
 */

export const SEVERITIES = Object.freeze(["P1", "P2", "P3"]);

export const CATEGORIES = Object.freeze([
  "database",
  "network",
  "compute",
  "security",
  "storage",
  "application"
]);

export const INCIDENT_TYPES_BY_CATEGORY = Object.freeze({
  database: Object.freeze([
    "replication_lag",
    "connection_exhaustion",
    "deadlock_spike",
    "disk_saturation",
    "backup_failure"
  ]),
  network: Object.freeze([
    "dns_resolution_failure",
    "tls_handshake_error",
    "packet_loss",
    "ingress_timeout",
    "certificate_expiry"
  ]),
  compute: Object.freeze([
    "oom_kill",
    "cpu_throttling",
    "pod_crashloop",
    "worker_starvation"
  ]),
  security: Object.freeze([
    "auth_brute_force",
    "credential_leak",
    "anomalous_egress",
    "waf_block_spike"
  ]),
  storage: Object.freeze([
    "iops_saturation",
    "volume_readonly",
    "object_store_5xx"
  ]),
  application: Object.freeze([
    "http_5xx_burst",
    "queue_backlog",
    "latency_degradation",
    "dependency_timeout"
  ])
});

export const ALL_INCIDENT_TYPES = Object.freeze(
  Object.values(INCIDENT_TYPES_BY_CATEGORY).flat()
);

export const INCIDENT_TYPE_TO_CATEGORY = Object.freeze(
  Object.fromEntries(
    Object.entries(INCIDENT_TYPES_BY_CATEGORY).flatMap(([category, types]) =>
      types.map((incidentType) => [incidentType, category])
    )
  )
);

export const SAFE_ACTIONS_BY_INCIDENT_TYPE = Object.freeze({
  replication_lag: "inspect_replication_slots_and_wal",
  connection_exhaustion: "capture_connection_pool_metrics",
  deadlock_spike: "collect_lock_graph_and_slow_queries",
  disk_saturation: "inspect_tablespace_and_temp_usage",
  backup_failure: "verify_snapshot_logs_and_retention",
  dns_resolution_failure: "verify_dns_resolvers_and_records",
  tls_handshake_error: "inspect_tls_chain_and_cipher_negotiation",
  packet_loss: "capture_traceroute_and_interface_drops",
  ingress_timeout: "inspect_upstream_health_and_lb_logs",
  certificate_expiry: "check_certificate_expiry_and_renewal_job",
  oom_kill: "collect_heap_dump_and_cgroup_limits",
  cpu_throttling: "inspect_cpu_cfs_quota_and_threads",
  pod_crashloop: "fetch_container_logs_and_exit_codes",
  worker_starvation: "inspect_worker_queue_and_concurrency",
  auth_brute_force: "audit_auth_logs_and_rate_limit_rules",
  credential_leak: "revoke_exposed_token_and_rotate_secret",
  anomalous_egress: "inspect_egress_flows_and_firewall_logs",
  waf_block_spike: "review_waf_rule_matches_and_ip_reputation",
  iops_saturation: "check_disk_queue_depth_and_io_wait",
  volume_readonly: "inspect_kernel_dmesg_and_mount_flags",
  object_store_5xx: "verify_storage_endpoint_status_and_retries",
  http_5xx_burst: "correlate_5xx_traces_and_recent_deploys",
  queue_backlog: "inspect_consumer_lag_and_dlq_depth",
  dependency_timeout: "check_downstream_latency_and_circuit_breakers"
});

export const FALLBACK_SAFE_ACTION = "escalate_to_oncall_for_manual_verification";

export const ALL_SAFE_ACTIONS = Object.freeze([
  ...new Set([
    ...Object.values(SAFE_ACTIONS_BY_INCIDENT_TYPE),
    FALLBACK_SAFE_ACTION
  ])
]);

export const TRIAGE_RESPONSE_SCHEMA = Object.freeze({
  name: "incident_triage",
  strict: true,
  schema: Object.freeze({
    type: "object",
    additionalProperties: false,
    required: [
      "severity",
      "category",
      "incidentType",
      "recommendedAction",
      "requiresHumanApproval",
      "summary"
    ],
    properties: Object.freeze({
      severity: Object.freeze({ type: "string", enum: [...SEVERITIES] }),
      category: Object.freeze({ type: "string", enum: [...CATEGORIES] }),
      incidentType: Object.freeze({ type: "string", enum: [...ALL_INCIDENT_TYPES] }),
      recommendedAction: Object.freeze({ type: "string", enum: [...ALL_SAFE_ACTIONS] }),
      requiresHumanApproval: Object.freeze({ type: "boolean" }),
      summary: Object.freeze({ type: "string", minLength: 5, maxLength: 320 })
    })
  })
});

export class GuardrailError extends Error {
  /**
   * @param {string} message
   * @param {{ code?: string, statusCode?: number, violations?: string[], detail?: unknown }} [meta]
   */
  constructor(message, meta = {}) {
    super(message);
    this.name = "GuardrailError";
    this.code = meta.code || "GUARDRAIL_VIOLATION";
    this.statusCode = Number(meta.statusCode) || 422;
    this.violations = Array.isArray(meta.violations) ? meta.violations : [];
    if (meta.detail !== undefined) this.detail = meta.detail;
  }
}

/**
 * Redacts authorization headers, Bearer/Basic tokens, and common API key shapes
 * before surfacing error strings to logs, health checks, or HTTP clients.
 * @param {unknown} value
 * @param {number} [maxLength=240]
 * @returns {string}
 */
export function redactSecrets(value, maxLength = 240) {
  const cleaned = String(value ?? "")
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 <redacted>")
    .replace(/\b(Authorization)\s*[:=]\s*[^\s,;]+(?:\s+[^\s,;]+)?/gi, "$1: <redacted>")
    .replace(/\b(sk-[A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{12,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g, "<redacted-key>")
    .replace(/\b(api[_-]?key|token|secret|password)\s*[:=]\s*["']?[^\s"',;]+["']?/gi, "$1=<redacted>")
    .replace(/[\t\r\n]+/g, " ")
    .trim();
  return maxLength > 0 ? cleaned.slice(0, maxLength) : cleaned;
}

/**
 * Serializes untrusted values into JSON with XML/HTML significant characters
 * escaped so payloads cannot break out of XML prompt fences.
 * @param {unknown} value
 * @returns {string}
 */
export function promptSafeJson(value) {
  const normalized = value === undefined ? null : value;
  return JSON.stringify(normalized)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

/**
 * Wraps untrusted incident metadata and event payload inside XML-delimited
 * JSON blocks for prompt-injection isolation.
 * @param {Record<string, unknown>} event
 * @returns {string}
 */
export function buildTriageUserContent(event = {}) {
  const contextBlock = {
    eventId: String(event.eventId || "evt-unknown").slice(0, 80),
    service: String(event.service || "unknown-service").slice(0, 80),
    environment: String(event.environment || "production").slice(0, 40),
    region: String(event.region || "global").slice(0, 40),
    source: String(event.source || "telemetry").slice(0, 60)
  };
  const payloadBlock = {
    message: String(event.message || ""),
    metrics: event.metrics && typeof event.metrics === "object" ? event.metrics : null
  };
  return [
    "<incident_context_json>",
    promptSafeJson(contextBlock),
    "</incident_context_json>",
    "<event_payload_json>",
    promptSafeJson(payloadBlock),
    "</event_payload_json>"
  ].join("\n");
}

function validateNode(value, schema, path, violations) {
  if (!schema || typeof schema !== "object") return;

  if (schema.type) {
    const validType = checkJsonType(value, schema.type);
    if (!validType) {
      violations.push(`${path} must be of type ${schema.type}`);
      return;
    }
  }

  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
    violations.push(`${path} value "${String(value)}" is outside the allowed catalog`);
  }

  if (typeof value === "string") {
    if (typeof schema.minLength === "number" && value.length < schema.minLength) {
      violations.push(`${path} length must be >= ${schema.minLength}`);
    }
    if (typeof schema.maxLength === "number" && value.length > schema.maxLength) {
      violations.push(`${path} length must be <= ${schema.maxLength}`);
    }
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
      violations.push(`${path} does not match required pattern`);
    }
  }

  if (typeof value === "number") {
    if (typeof schema.minimum === "number" && value < schema.minimum) {
      violations.push(`${path} must be >= ${schema.minimum}`);
    }
    if (typeof schema.maximum === "number" && value > schema.maximum) {
      violations.push(`${path} must be <= ${schema.maximum}`);
    }
  }

  if (schema.type === "array" && Array.isArray(value) && schema.items) {
    value.forEach((item, index) => validateNode(item, schema.items, `${path}[${index}]`, violations));
  }

  if (schema.type === "object" && value && typeof value === "object" && !Array.isArray(value)) {
    const properties = schema.properties || {};
    const required = Array.isArray(schema.required) ? schema.required : [];
    for (const key of required) {
      if (!Object.hasOwn(value, key) || value[key] === undefined) {
        violations.push(`${path}.${key} is required`);
      }
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.hasOwn(properties, key)) {
          violations.push(`${path}.${key} is not allowed (additionalProperties: false)`);
        }
      }
    }
    for (const [key, propSchema] of Object.entries(properties)) {
      if (Object.hasOwn(value, key) && value[key] !== undefined) {
        validateNode(value[key], propSchema, `${path}.${key}`, violations);
      }
    }
  }
}

function checkJsonType(value, expectedType) {
  switch (expectedType) {
    case "object":
      return value !== null && typeof value === "object" && !Array.isArray(value);
    case "array":
      return Array.isArray(value);
    case "string":
      return typeof value === "string";
    case "boolean":
      return typeof value === "boolean";
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "null":
      return value === null;
    default:
      return false;
  }
}

/**
 * Strictly validates an object against a JSON Schema subset without mutating
 * or coercing field values. Throws GuardrailError on any schema or catalog violation.
 * @param {unknown} payload
 * @param {object} [schema]
 * @returns {Record<string, unknown>}
 */
export function validateStrictJsonSchema(payload, schema = TRIAGE_RESPONSE_SCHEMA.schema) {
  const violations = [];
  validateNode(payload, schema, "$", violations);
  if (violations.length > 0) {
    throw new GuardrailError(
      `Schema validation failed: ${violations.join("; ")}`,
      {
        code: "SCHEMA_VALIDATION_FAILED",
        statusCode: 422,
        violations
      }
    );
  }
  return /** @type {Record<string, unknown>} */ (payload);
}

const DESTRUCTIVE_ACTION_ID_RE = /^(?:drop|delete|truncate|destroy|wipe|purge|format|terminate|kill|reboot|shutdown|force_failover|disable_auth|disable_firewall)(?:$|[_-])/i;

const DESTRUCTIVE_COMMAND_PATTERNS = [
  /\b(?:drop\s+(?:database|table|schema|cluster|index)|truncate\s+table|delete\s+from\s+[a-z_][a-z0-9_]*)\b/i,
  /\b(?:rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r|mkfs(?:\.[a-z0-9]+)?|wipefs|dd\s+if=\S+\s+of=\/dev\/)\b/i,
  /\b(?:kubectl\s+delete\s+(?:namespace|ns|pvc|pv|deployment|statefulset|pod|node)|terraform\s+destroy|helm\s+uninstall)\b/i,
  /\b(?:kill\s+-9|pkill\s+-9|shutdown\s+-[hr]|reboot\s+-f|systemctl\s+stop\s+\S+|terminate[- ]instances?|delete[- ]db[- ]instance)\b/i,
  /\b(?:format[- ]disk|wipe\s+(?:volume|disk|data)|purge\s+all)\b/i
];

const PROMPT_TAG_BREAKOUT_RE = /<\/?(?:incident_context_json|event_payload_json|script|system)\b/i;

/**
 * Inspects model output fields for destructive action identifiers, shell/SQL
 * destructive commands, or raw prompt-fence breakout tags.
 * @param {unknown} candidate
 * @returns {{ destructive: boolean, reason: string | null }}
 */
export function detectDestructiveOutput(candidate) {
  if (!candidate || typeof candidate !== "object") {
    return { destructive: false, reason: null };
  }
  const action = String(candidate.recommendedAction || "").trim();
  if (DESTRUCTIVE_ACTION_ID_RE.test(action)) {
    return {
      destructive: true,
      reason: `Destructive recommendedAction "${action}" is blocked by policy.`
    };
  }

  const textFields = [
    action,
    candidate.summary,
    candidate.command,
    candidate.remediation,
    ...(Array.isArray(candidate.commands) ? candidate.commands : []),
    ...(Array.isArray(candidate.steps) ? candidate.steps : [])
  ]
    .filter((item) => item !== undefined && item !== null)
    .map((item) => String(item));

  for (const fieldText of textFields) {
    if (PROMPT_TAG_BREAKOUT_RE.test(fieldText)) {
      return {
        destructive: true,
        reason: "Unsafe XML/HTML breakout tag detected in model output."
      };
    }
    for (const pattern of DESTRUCTIVE_COMMAND_PATTERNS) {
      const match = fieldText.match(pattern);
      if (match) {
        return {
          destructive: true,
          reason: `Destructive command pattern "${match[0]}" is blocked by policy.`
        };
      }
    }
  }
  return { destructive: false, reason: null };
}

/**
 * Normalizes summary text to clean, plain ASCII operational phrasing.
 * @param {unknown} value
 * @returns {string}
 */
export function sanitizeSummary(value) {
  return String(value ?? "")
    .replace(/^(?:summary|remark|recommendation|note)\s*:\s*/i, "")
    .replace(/\b(?:please note that|it is important to note that|it should be noted that|overall,)\s*/gi, "")
    .replace(/\s*[—–]\s*/g, ", ")
    .replace(/[\t\r\n]+/g, " ")
    .replace(/[<>]/g, "")
    .replace(/\s{2,}/g, " ")
    .trim()
    .slice(0, 320);
}

const CREDENTIAL_LEAK_EVIDENCE_RE = /\b(?:credential leak|api key leaked|secret exposed|exposed token|private key committed|auth bypass|leaked credentials?)\b/i;
const CRITICAL_BLAST_RADIUS_RE = /\b(?:all tenants|multi[- ]?az|complete outage|total outage|primary down|read[- ]only filesystem|cannot accept writes|write stalls?|100% error|zero healthy backends|unhealthy targets 100%|wal.{0,20}(?:9[5-9]|100)%|disk.{0,20}(?:9[89]|100)%)\b/i;
const NON_PROD_ENV_RE = /^(?:staging|stage|dev|development|sandbox|qa|test|synthetic)$/i;
const NON_PROD_TEXT_RE = /\b(?:staging environment|dev cluster|sandbox environment|synthetic drill|dry[- ]run)\b/i;

/**
 * Deterministic incident triage policy engine:
 * 1. Blocks destructive commands/actions in model outputs.
 * 2. Strictly enforces JSON Schema & catalog membership.
 * 3. Aligns cross-field taxonomy and applies deterministic severity/approval calibration.
 *
 * @param {Record<string, unknown>} rawSuggestion
 * @param {Record<string, unknown>} [event]
 * @param {{ strictCategoryMatch?: boolean, strictActionMatch?: boolean }} [options]
 * @returns {Record<string, unknown>}
 */
export function applyTriagePolicy(rawSuggestion, event = {}, options = {}) {
  const destructiveCheck = detectDestructiveOutput(rawSuggestion);
  if (destructiveCheck.destructive) {
    throw new GuardrailError(destructiveCheck.reason, {
      code: "DESTRUCTIVE_ACTION_BLOCKED",
      statusCode: 422,
      violations: [destructiveCheck.reason]
    });
  }

  validateStrictJsonSchema(rawSuggestion, TRIAGE_RESPONSE_SCHEMA.schema);

  const result = {
    severity: rawSuggestion.severity,
    category: rawSuggestion.category,
    incidentType: rawSuggestion.incidentType,
    recommendedAction: rawSuggestion.recommendedAction,
    requiresHumanApproval: rawSuggestion.requiresHumanApproval,
    summary: sanitizeSummary(rawSuggestion.summary)
  };

  if (result.summary.length < 5) {
    throw new GuardrailError("Sanitized summary must contain at least 5 characters.", {
      code: "SCHEMA_VALIDATION_FAILED",
      statusCode: 422,
      violations: ["$.summary length after sanitization is < 5"]
    });
  }

  const policyFlags = [];
  const expectedCategory = INCIDENT_TYPE_TO_CATEGORY[result.incidentType];
  if (result.category !== expectedCategory) {
    if (options.strictCategoryMatch) {
      throw new GuardrailError(
        `Incident type "${result.incidentType}" does not belong to category "${result.category}".`,
        {
          code: "CATALOG_MISMATCH",
          statusCode: 422,
          violations: [`$.category expected "${expectedCategory}" for incidentType "${result.incidentType}"`]
        }
      );
    }
    result.category = expectedCategory;
    policyFlags.push("category_aligned_to_incident_type");
  }

  const canonicalAction = SAFE_ACTIONS_BY_INCIDENT_TYPE[result.incidentType];
  if (result.recommendedAction !== canonicalAction && result.recommendedAction !== FALLBACK_SAFE_ACTION) {
    if (options.strictActionMatch) {
      throw new GuardrailError(
        `Recommended action "${result.recommendedAction}" does not match incidentType "${result.incidentType}".`,
        {
          code: "CATALOG_MISMATCH",
          statusCode: 422,
          violations: [`$.recommendedAction expected "${canonicalAction}" for incidentType "${result.incidentType}"`]
        }
      );
    }
    result.recommendedAction = canonicalAction;
    policyFlags.push("action_aligned_to_incident_type");
  }

  const environment = String(event?.environment || "").trim();
  const evidence = `${String(event?.service || "")} ${environment} ${String(event?.message || "")}`.trim();
  const isNonProd = NON_PROD_ENV_RE.test(environment) || NON_PROD_TEXT_RE.test(evidence);
  const isCredentialLeak = result.incidentType === "credential_leak" || CREDENTIAL_LEAK_EVIDENCE_RE.test(evidence);
  const hasCriticalBlastRadius = CRITICAL_BLAST_RADIUS_RE.test(evidence);

  if (isCredentialLeak && !isNonProd) {
    if (result.severity !== "P1") {
      result.severity = "P1";
      policyFlags.push("critical_security_escalation");
    }
    if (result.category !== "security" || result.incidentType !== "credential_leak") {
      result.category = "security";
      result.incidentType = "credential_leak";
      policyFlags.push("security_taxonomy_enforced");
    }
    if (result.recommendedAction !== SAFE_ACTIONS_BY_INCIDENT_TYPE.credential_leak) {
      result.recommendedAction = SAFE_ACTIONS_BY_INCIDENT_TYPE.credential_leak;
      policyFlags.push("security_action_enforced");
    }
  } else if (isNonProd) {
    if (result.severity !== "P3") {
      result.severity = "P3";
      policyFlags.push("non_production_severity_cap");
    }
    if (result.category !== "security" && result.requiresHumanApproval) {
      result.requiresHumanApproval = false;
      policyFlags.push("non_production_approval_relaxed");
    }
  } else if (hasCriticalBlastRadius) {
    if (result.severity !== "P1") {
      result.severity = "P1";
      policyFlags.push("critical_blast_radius_escalation");
    }
  }

  if ((result.severity === "P1" || result.category === "security") && !result.requiresHumanApproval) {
    result.requiresHumanApproval = true;
    policyFlags.push("human_approval_enforced");
  }

  const summaryChanged = result.summary !== rawSuggestion.summary;
  if (summaryChanged) policyFlags.push("summary_sanitized");

  return {
    ...result,
    policyFlags,
    policyAdjusted: policyFlags.length > 0,
    policyReason: policyFlags.join(", ") || null
  };
}
