export type RunItem = {
  run_id: string;
  config_id: string;
  research_question: string;
  run_type: string;
  scenario_id: string | null;
  dataset_id: string | null;
  status: string;
  started_at: string;
  completed_at: string | null;
  red_score: string | number | null;
  blue_score: string | number | null;
};

export type Overview = {
  total_runs: number;
  status_counts: Record<string, number>;
  research_question_counts: Record<string, number>;
  recent_runs: RunItem[];
};

export type ScoreBreakdown = {
  run_id: string;
  score_type: string;
  scoring_version: string;
  selected_patch_attempt: number | null;
  components: Array<{
    component_id: string;
    observed: boolean;
    points_possible: number;
    points_awarded: number;
    evidence_ids: string[];
  }>;
  penalties: Array<{
    penalty_id: string;
    observed_count: number;
    counted_occurrences: number;
    points_per_occurrence: number;
    points_deducted: number;
    evidence_ids: string[];
  }>;
  attributed_policy_event_ids: string[];
  subtotal: number;
  total_penalty: number;
  final_score: number;
};

export type RunScores = {
  run_id: string;
  applicability: string;
  scores: Array<{
    score_type: string;
    score_value: string | number;
    scoring_version: string;
    evidence_reference: string;
    evidence_sha256: string | null;
    evidence_integrity: boolean;
    breakdown: ScoreBreakdown | null;
  }>;
};

export type PatchVerification = {
  run_id: string;
  attempts: Array<{
    attempt_number: number;
    final_state: string | null;
    patch_decision: string | null;
    prepared_diff_sha256: string | null;
    files_changed: number | null;
    inserted_lines: number | null;
    deleted_lines: number | null;
    total_diff_bytes: number | null;
    changed_paths: string[];
    rejection_reason: string | null;
    failure_reason: string | null;
    accepted_commit_sha: string | null;
    diff_excerpt: string | null;
    diff_truncated: boolean;
    stages: Array<{
      stage_id: string;
      sequence_number: number;
      required: boolean;
      passed: boolean;
      duration_ms: number;
      details: string;
      checks: Array<{
        check_id: string;
        status: string;
        duration_ms: number;
        details: string;
      }>;
    }>;
  }>;
};

// Original research backend can still be overridden independently.
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "/api";

export type ApiErrorKind = "http" | "network" | "timeout" | "aborted" | "schema";

export class ApiRequestError extends Error {
  constructor(public readonly kind: ApiErrorKind, detail: string, public readonly status?: number) {
    super(detail);
    this.name = "ApiRequestError";
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const stringField = (value: Record<string, unknown>, field: string) => typeof value[field] === "string";
const booleanField = (value: Record<string, unknown>, field: string) => typeof value[field] === "boolean";
const countMap = (value: unknown): boolean =>
  isRecord(value) && Object.values(value).every(n => Number.isSafeInteger(n) && (n as number) >= 0);

function isRun(value: unknown): boolean {
  return isRecord(value) && ["run_id", "config_id", "research_question", "run_type", "status", "started_at"].every(key => stringField(value, key)) &&
    ["scenario_id", "dataset_id", "completed_at"].every(key => value[key] === null || stringField(value, key)) &&
    ["red_score", "blue_score"].every(key => value[key] === null || ["string", "number"].includes(typeof value[key]));
}

function validateResponse(url: string, data: unknown): boolean {
  const path = url.split("?")[0];
  if (path === API_BASE + "/health") {
    return isRecord(data) && data.status === "ok" && data.database_read_only === true &&
      (data.database_available === undefined || typeof data.database_available === "boolean");
  }
  if (path === API_BASE + "/overview") {
    return isRecord(data) && Number.isSafeInteger(data.total_runs) && (data.total_runs as number) >= 0 &&
      countMap(data.status_counts) && countMap(data.research_question_counts) &&
      Array.isArray(data.recent_runs) && data.recent_runs.every(isRun);
  }
  if (path === API_BASE + "/runs") return Array.isArray(data) && data.every(isRun);
  if (path === "/api/console/status") {
    return isRecord(data) && stringField(data, "target") && stringField(data, "execution_mode") &&
      stringField(data, "experience_mode") && isRecord(data.model) &&
      stringField(data.model, "state") && booleanField(data.model, "final_research_ready");
  }
  if (path === "/api/console/models/local") {
    return isRecord(data) && booleanField(data, "model_directory_configured") &&
      Array.isArray(data.models) && data.models.every((model: unknown) =>
        isRecord(model) && stringField(model, "filename") &&
        typeof model.bytes === "number" && Number.isFinite(model.bytes) && model.bytes >= 0);
  }
  if (path === "/api/console/scenarios") {
    return Array.isArray(data) && data.every((item: unknown) =>
      isRecord(item) && ["id", "title", "registered_test", "vector", "remediation"].every(key => stringField(item,key)));
  }
  if (path === "/api/mars/plans") {
    return Array.isArray(data) ? data.every(isMarsPlan) : isMarsPlan(data);
  }
  if (path === "/api/console/preview") {
    return isRecord(data) && ["scenario", "title", "registered_test_id", "prepared_diff_sha256", "diff_preview", "notice"].every(key => stringField(data,key)) &&
      ["prepared", "applied", "verified", "final_research"].every(key => booleanField(data,key));
  }
  return true; // Other archived evidence cannot acquire authority by a generic cast.
}

export async function requestJson<T>(url: string, options?: RequestInit, timeoutMs = 20000): Promise<T> {
  const controller = new AbortController();
  let timedOut = false;
  const externalAbort = () => controller.abort();
  if (options?.signal?.aborted) controller.abort();
  options?.signal?.addEventListener("abort", externalAbort, { once: true });
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
  try {
    const response = await fetch(url, {
      method: "GET", headers: { Accept: "application/json" }, ...options,
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new ApiRequestError("http", "Local API returned HTTP " + response.status, response.status);
    }
    let value: unknown;
    try { value = await response.json(); }
    catch { throw new ApiRequestError("schema", "Local API returned invalid JSON"); }
    if (!validateResponse(url, value)) {
      throw new ApiRequestError("schema", "Local API response did not match its data contract");
    }
    return value as T;
  } catch (error) {
    if (error instanceof ApiRequestError) throw error;
    if (timedOut) throw new ApiRequestError("timeout", "Local API request timed out");
    if (controller.signal.aborted) throw new ApiRequestError("aborted", "Local API request was cancelled");
    throw new ApiRequestError("network", "Local API is unreachable");
  } finally {
    clearTimeout(timer);
    options?.signal?.removeEventListener("abort", externalAbort);
  }
}

export function getJson<T>(path: string, options?: RequestInit): Promise<T> {
  return requestJson<T>(API_BASE + path, options);
}

export function getConsoleJson<T>(path: string, options?: RequestInit): Promise<T> {
  return requestJson<T>("/api/console" + path, options);
}

export type DevelopmentEvidence = {
  red: {
    status: string;
    red_evidence_verified: boolean;
    exploit_confirmed: boolean | null;
    registered_test_id: string | null;
    red_run_id: string | null;
  };
  blue: {
    status: string;
    model_origin?: string;
    model_input_scope?: string;
    model_decision?: { classification: string } | null;
    red_evidence_verified?: boolean;
    source_analysis_authorized?: boolean;
    registered_test_id?: string | null;
    red_run_id?: string | null;
  };
  sqli: {
    status: string;
    registered_replay_verified: boolean;
    exploit_confirmed: boolean | null;
    test_id: string | null;
    run_id: string | null;
    legitimate_login_verified: boolean;
    search_file_verified: boolean;
  };
  phase5: {
    status: string;
    replay_count: number;
    results: Record<string, {
      registered_test_id: string;
      run_id: string;
      registered_replay_verified: boolean;
      baseline_exploit_confirmed: boolean;
      patched_exploit_confirmed: boolean;
      offline_functional_verified: boolean;
      patched_docker_functional_verified: boolean;
    }>;
    model_driven_red_selection_verified: boolean;
    patched_docker_functional_verified: boolean;
    final_research_qualified: boolean;
  };
};


// Only the three existing synthetic registrations are displayed or submitted.
// The server independently enforces its own strict allowlist.
export const PREVIEW_TEST_IDS = {
  sql: "sqli-login-bypass-001",
  xss: "xss-reflection-001",
  traversal: "path-traversal-private-file-001",
} as const;
export type ScenarioKey = keyof typeof PREVIEW_TEST_IDS;

export type RegisteredScenario = {
  id: string;
  title: string;
  registered_test: string;
  vector: string;
  remediation: string;
};

export type TrustedPreview = {
  scenario: string;
  title: string;
  registered_test_id: string;
  prepared: boolean;
  applied: boolean;
  verified: boolean;
  final_research: boolean;
  prepared_diff_sha256: string;
  diff_preview: string;
  notice: string;
};

export function prepareConsolePreview(scenario: ScenarioKey): Promise<TrustedPreview> {
  if (!Object.hasOwn(PREVIEW_TEST_IDS, scenario)) {
    return Promise.reject(new Error("Unregistered scenario refused"));
  }
  return requestJson<TrustedPreview>("/api/console/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ scenario }),
  });
}


// Existing local operator endpoints. User actions only; no automatic model execution.
export function startLocalModel(filename: string, model_name: string): Promise<unknown> {
  if (!filename.endsWith(".gguf") || !/^[a-zA-Z0-9][a-zA-Z0-9._:/+\-]{0,127}$/.test(model_name)) {
    return Promise.reject(new Error("Select a GGUF file and valid model identifier."));
  }
  return requestJson("/api/console/models/load", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ filename, model_name }),
  }, 30000);
}

export function stopLocalModel(): Promise<unknown> {
  return requestJson("/api/console/models/unload", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: "{}",
  });
}


export type MarsPlan = {
  id: string; name: string; scenario: ScenarioKey; target_id: string;
  registered_test_id: string; route: string; created_at: string;
  status: "draft"; execution_enabled: false; executed: false;
  final_research_qualified: false;
};

function isMarsPlan(value: unknown): boolean {
  return isRecord(value) && ["id", "name", "scenario", "target_id",
    "registered_test_id", "route", "created_at"].every(field => stringField(value, field)) &&
    ["sql", "xss", "traversal"].includes(value.scenario as string) &&
    value.status === "draft" && value.execution_enabled === false &&
    value.executed === false && value.final_research_qualified === false;
}

export function listMarsPlans(): Promise<MarsPlan[]> {
  return requestJson<MarsPlan[]>("/api/mars/plans");
}

export function createMarsPlan(name: string, scenario: ScenarioKey): Promise<MarsPlan> {
  return requestJson<MarsPlan>("/api/mars/plans", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ name, scenario }),
  });
}

export async function deleteMarsPlan(id: string): Promise<void> {
  if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error("Invalid assessment draft identifier");
  const response = await fetch("/api/mars/plans/" + encodeURIComponent(id), { method: "DELETE" });
  if (response.status !== 204) throw new ApiRequestError("http", "Draft deletion failed", response.status);
}


export type MarsJobState = "awaiting_review" | "scope_reviewed" | "cancelled";
export type MarsJob = {
  id: string; plan_id: string; name: string; scenario: ScenarioKey;
  target_id: string; registered_test_id: string; route: string;
  method: string; endpoint_path: string; max_requests: number;
  timeout_seconds: number; scope_sha256: string;
  created_at: string; updated_at: string; state: MarsJobState;
  execution_authorized: false; executed: false; final_research_qualified: false;
};

export type MarsJobEvent = { sequence: number; event: string; occurred_at: string };

function isMarsJob(value: unknown): value is MarsJob {
  return isRecord(value) &&
    ["id", "plan_id", "name", "scenario", "target_id", "registered_test_id",
      "route", "method", "endpoint_path", "scope_sha256", "created_at", "updated_at", "state"]
      .every(field => stringField(value, field)) &&
    ["awaiting_review", "scope_reviewed", "cancelled"].includes(value.state as string) &&
    Number.isSafeInteger(value.max_requests) && (value.max_requests as number) > 0 &&
    Number.isSafeInteger(value.timeout_seconds) && (value.timeout_seconds as number) > 0 &&
    value.execution_authorized === false && value.executed === false &&
    value.final_research_qualified === false;
}
function isMarsJobEvent(value: unknown): boolean {
  return isRecord(value) && Number.isSafeInteger(value.sequence) &&
    (value.sequence as number) > 0 && stringField(value, "event") && stringField(value, "occurred_at");
}

export function listMarsJobs(): Promise<MarsJob[]> {
  return requestJson<MarsJob[]>("/api/mars/jobs").then(data => {
    if (!Array.isArray(data) || !data.every(isMarsJob))
      throw new ApiRequestError("schema", "Invalid MARS job records");
    return data;
  });
}

export function createMarsJob(planId: string): Promise<MarsJob> {
  return requestJson<MarsJob>("/api/mars/jobs", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ plan_id: planId }),
  }).then(job => {
    if (!isMarsJob(job)) throw new ApiRequestError("schema", "Invalid prepared job");
    return job;
  });
}

export function updateMarsJob(id: string, action: "review" | "cancel"): Promise<MarsJob> {
  return requestJson<MarsJob>("/api/mars/jobs/" + encodeURIComponent(id) + "/" + action, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
  }).then(job => {
    if (!isMarsJob(job)) throw new ApiRequestError("schema", "Invalid job transition");
    return job;
  });
}

export function getMarsJobEvents(id: string): Promise<MarsJobEvent[]> {
  return requestJson<MarsJobEvent[]>("/api/mars/jobs/" + encodeURIComponent(id) + "/events")
    .then(events => {
      if (!Array.isArray(events) || !events.every(isMarsJobEvent))
        throw new ApiRequestError("schema", "Invalid job history");
      return events;
    });
}


export type MarsRedPreflight = {
  schema_version: "mars-red-preflight-v1";
  job_id: string;
  registered_test_id: string;
  scope_sha256: string;
  scope_current: boolean;
  checks: {
    job_scope_reviewed: boolean;
    registered_scope_current: boolean;
    independent_admission_verified: false;
    isolated_runtime_verified: false;
    runner_enabled: false;
  };
  can_dispatch: false;
  note: string;
};

export async function getMarsRedPreflight(id: string): Promise<MarsRedPreflight> {
  const data: unknown = await requestJson("/api/mars/jobs/" +
    encodeURIComponent(id) + "/preflight");
  if (!isRecord(data) || data.schema_version !== "mars-red-preflight-v1" ||
      data.job_id !== id || !stringField(data, "registered_test_id") ||
      !stringField(data, "scope_sha256") ||
      !/^[0-9a-f]{64}$/.test(data.scope_sha256 as string) ||
      typeof data.scope_current !== "boolean" || !isRecord(data.checks) ||
      !booleanField(data.checks, "job_scope_reviewed") ||
      !booleanField(data.checks, "registered_scope_current") ||
      data.checks.independent_admission_verified !== false ||
      data.checks.isolated_runtime_verified !== false ||
      data.checks.runner_enabled !== false ||
      data.can_dispatch !== false || !stringField(data, "note")) {
    throw new ApiRequestError("schema", "Unsafe or malformed Red preflight response");
  }
  return data as MarsRedPreflight;
}
