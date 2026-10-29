import { ApiRequestError, requestJson } from "../api";

export const assessmentStatuses = [
  "created", "awaiting_authorization", "queued", "running", "completed",
  "completed_with_limitations", "failed", "cancelled", "blocked",
] as const;
export type RedAssessmentStatus = typeof assessmentStatuses[number];
export type RedStageStatus = "not_started" | "ready" | "queued" | "running" |
  "succeeded" | "failed" | "blocked" | "cancelled" | "stale";

export type RedTarget = {
  target_id: string;
  compatibility: "supported";
  supported_classes: Array<"path_traversal" | "sql_injection" | "xss">;
  limitations: Array<"unauthenticated_only">;
  standard_budget: RedStandardBudget;
};

export type RedStandardBudget = {
  profile: "standard";
  max_http_requests: number;
  max_crawl_requests: number;
  max_tests: number;
  max_runtime_seconds: number;
  max_parallel_operations: number;
  max_depth: number;
  max_retries: number;
  max_cpu_cores: number;
  max_memory_mb: number;
};

export type RedCommandReceipt = {
  assessment_id: string;
  request_id: string;
  status: "awaiting_authorization" | "queued" | "cancelled" | "cancellation_requested";
  job_ids: string[];
};

export type RedDashboardSummary = {
  target_id: string | null;
  assessment_count: number;
  confirmed_findings: number;
  suspected_findings: number;
  tested: number;
  eligible: number;
  active_assessments: number;
  queued_assessments: number;
  active_stages: number;
  coverage_gaps: number;
};

export type RedAssessment = {
  assessment_id: string;
  target_id: string;
  mode: "manual" | "autonomous";
  profile: "standard";
  status: RedAssessmentStatus;
  workflow_complete: boolean;
  coverage: {
    eligible: number; executed: number; completed: number; blocked: number;
    skipped: number; observed_candidate_gaps: number;
    unresolved_observations: number; coverage_complete: boolean;
  };
  current_plan_version: string | null;
  current_surface_revision: string | null;
  stage_statuses: Partial<Record<"reconnaissance" | "planning" | "execution" | "verification", RedStageStatus>>;
};

type Page<T> = {
  items: T[];
  pagination: { offset: number; limit: number; total: number };
};

export type RedEvent = { event_id: string; action: string; status: string;
  stage: "reconnaissance" | "planning" | "execution" | "verification" | null;
  occurred_at: string };
export type RedFinding = { finding_id: string; assessment_id: string; target_id: string;
  status: "suspected" | "confirmed" | "not_confirmed" | "inconclusive";
  severity: "informational" | "low" | "medium" | "high" | "critical" | null;
  category: string | null; route: string | null; provenance: "controlled_http" | "zap" | null;
  reproduction_scope: "registered_local_lab" | "targeted_scanner" | null; has_evidence: boolean };
export type RedFindingDetail = { finding: RedFinding; operation_id: string; plan_version: string;
  test_id: string | null; oracle_id: string | null; evidence_receipt_ids: string[];
  evidence: Array<{ evidence_id: string; receipt_id: string; operation_id: string | null;
    sha256: string; content_type: string }> };
export type RedCoverageGap = { gap_id: string; status: "open" | "resolved";
  reason: string; candidate_id: string | null; test_id: string | null;
  recommendation: string | null };
export type RedCoverage = { assessment_id: string; target_id: string;
  coverage: RedAssessment["coverage"]; gaps: RedCoverageGap[]; warnings: string[] };
export type RedWorkspace = { assessment: RedAssessment;
  stages: Array<{ stage: keyof RedAssessment["stage_statuses"]; status: RedStageStatus;
    plan_version: string | null }>;
  plans: Array<{ plan_version: string; surface_revision: string;
    status: "draft" | "approved" | "stale" }>;
  candidate_count: number; planned_operation_count: number;
  finding_counts: Record<RedFinding["status"], number>; coverage_gap_count: number };
export type RedWorkspaceBundle = { workspace: RedWorkspace; events: RedEvent[];
  findings: RedFinding[]; findingTotal: number; coverage: RedCoverage };

export const assessmentPageSize = 25;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const isCount = (value: unknown) => Number.isSafeInteger(value) && Number(value) >= 0;
const isText = (value: unknown) => typeof value === "string" && value.length > 0;
const allowedStages = new Set<RedStageStatus>([
  "not_started", "ready", "queued", "running", "succeeded", "failed",
  "blocked", "cancelled", "stale",
]);

function isPagination(value: unknown): boolean {
  return isRecord(value) && isCount(value.offset) && isCount(value.total) &&
    Number.isSafeInteger(value.limit) && Number(value.limit) >= 1 && Number(value.limit) <= 200;
}

function isTarget(value: unknown): value is RedTarget {
  return isRecord(value) && isText(value.target_id) && value.compatibility === "supported" &&
    Array.isArray(value.supported_classes) && value.supported_classes.every(item =>
      ["path_traversal", "sql_injection", "xss"].includes(String(item))) &&
    Array.isArray(value.limitations) && value.limitations.every(item => item === "unauthenticated_only") &&
    isStandardBudget(value.standard_budget);
}

function isStandardBudget(value: unknown): value is RedStandardBudget {
  return isRecord(value) && value.profile === "standard" &&
    ["max_http_requests", "max_crawl_requests", "max_tests", "max_runtime_seconds",
      "max_parallel_operations", "max_depth", "max_retries", "max_memory_mb"]
      .every(field => isCount(value[field])) &&
    typeof value.max_cpu_cores === "number" && Number.isFinite(value.max_cpu_cores) &&
    value.max_cpu_cores > 0;
}

function isCommandReceipt(value: unknown): value is RedCommandReceipt {
  return isRecord(value) && isText(value.assessment_id) && isText(value.request_id) &&
    ["awaiting_authorization", "queued", "cancelled", "cancellation_requested"]
      .includes(String(value.status)) &&
    Array.isArray(value.job_ids) && value.job_ids.every(isText);
}

function isSummary(value: unknown): value is RedDashboardSummary {
  if (!isRecord(value) || !(value.target_id === null || isText(value.target_id))) return false;
  return ["assessment_count", "confirmed_findings", "suspected_findings", "tested",
    "eligible", "active_assessments", "queued_assessments", "active_stages",
    "coverage_gaps"].every(field => isCount(value[field]));
}

function isCoverageCounts(value: unknown): value is RedAssessment["coverage"] {
  return isRecord(value) && ["eligible", "executed", "completed", "blocked", "skipped",
    "observed_candidate_gaps", "unresolved_observations"].every(field => isCount(value[field])) &&
    typeof value.coverage_complete === "boolean";
}

function isAssessment(value: unknown): value is RedAssessment {
  if (!isRecord(value) || !isText(value.assessment_id) || !isText(value.target_id) ||
      !["manual", "autonomous"].includes(String(value.mode)) || value.profile !== "standard" ||
      !assessmentStatuses.includes(value.status as RedAssessmentStatus) ||
      typeof value.workflow_complete !== "boolean" || !isCoverageCounts(value.coverage) ||
      !(value.current_plan_version === null || isText(value.current_plan_version)) ||
      !(value.current_surface_revision === null || isText(value.current_surface_revision)) ||
      !isRecord(value.stage_statuses)) return false;
  return Object.entries(value.stage_statuses).every(([stage, status]) =>
    ["reconnaissance", "planning", "execution", "verification"].includes(stage) &&
    allowedStages.has(status as RedStageStatus));
}

function isEvent(value: unknown): value is RedEvent {
  return isRecord(value) && isText(value.event_id) && isText(value.action) &&
    isText(value.status) && (value.stage === null ||
      ["reconnaissance", "planning", "execution", "verification"].includes(String(value.stage))) &&
    isText(value.occurred_at) && !Number.isNaN(Date.parse(String(value.occurred_at)));
}

function isFinding(value: unknown): value is RedFinding {
  return isRecord(value) && ["finding_id", "assessment_id", "target_id"].every(key => isText(value[key])) &&
    ["suspected", "confirmed", "not_confirmed", "inconclusive"].includes(String(value.status)) &&
    (value.severity === null || ["informational", "low", "medium", "high", "critical"].includes(String(value.severity))) &&
    (value.category === null || isText(value.category)) && (value.route === null || isText(value.route)) &&
    (value.provenance === null || ["controlled_http", "zap"].includes(String(value.provenance))) &&
    (value.reproduction_scope === null || ["registered_local_lab", "targeted_scanner"].includes(String(value.reproduction_scope))) &&
    typeof value.has_evidence === "boolean";
}

function isWorkspace(value: unknown): value is RedWorkspace {
  const counts = isRecord(value) && isRecord(value.finding_counts) ? value.finding_counts : null;
  return isRecord(value) && isAssessment(value.assessment) && Array.isArray(value.stages) &&
    value.stages.every(item => isRecord(item) &&
      ["reconnaissance", "planning", "execution", "verification"].includes(String(item.stage)) &&
      allowedStages.has(item.status as RedStageStatus) &&
      (item.plan_version === null || isText(item.plan_version))) &&
    Array.isArray(value.plans) && value.plans.every(item => isRecord(item) &&
      isText(item.plan_version) && isText(item.surface_revision) &&
      ["draft", "approved", "stale"].includes(String(item.status))) &&
    isCount(value.candidate_count) && isCount(value.planned_operation_count) &&
    counts !== null && ["suspected", "confirmed", "not_confirmed", "inconclusive"]
      .every(key => isCount(counts[key])) &&
    isCount(value.coverage_gap_count);
}

function isFindingPage(value: unknown): value is Page<RedFinding> & { coverage_gap_count: number } {
  if (!isRecord(value) || !isCount(value.coverage_gap_count)) return false;
  return isPage(value, isFinding);
}

function isCoverageBundle(value: unknown): value is RedCoverage {
  return isRecord(value) && isText(value.assessment_id) && isText(value.target_id) &&
    isCoverageCounts(value.coverage) && Array.isArray(value.gaps) && value.gaps.every(item =>
      isRecord(item) && isText(item.gap_id) && ["open", "resolved"].includes(String(item.status)) &&
      isText(item.reason) && (item.candidate_id === null || isText(item.candidate_id)) &&
      (item.test_id === null || isText(item.test_id)) &&
      (item.recommendation === null || isText(item.recommendation))) &&
    Array.isArray(value.warnings) && value.warnings.every(isText);
}

function isPage<T>(value: unknown, itemGuard: (item: unknown) => item is T): value is Page<T> {
  return isRecord(value) && Array.isArray(value.items) && value.items.every(itemGuard) &&
    isPagination(value.pagination);
}

async function redGet<T>(
  path: string,
  token: string,
  guard: (value: unknown) => value is T,
  signal?: AbortSignal,
): Promise<T> {
  const value = await requestJson<unknown>(path, {
    headers: { Accept: "application/json", Authorization: `Bearer ${token}` },
    signal,
  });
  if (!guard(value)) throw new ApiRequestError("schema", "Red API response did not match its data contract");
  return value;
}

export function listRedTargets(token: string, signal?: AbortSignal): Promise<Page<RedTarget>> {
  return redGet("/api/red/targets?offset=0&limit=200", token,
    value => isPage(value, isTarget), signal);
}

export async function loadRedDashboard(
  token: string,
  filters: { targetId: string; status: string; offset?: number },
  signal?: AbortSignal,
): Promise<{ summary: RedDashboardSummary; assessments: Page<RedAssessment> }> {
  const query = new URLSearchParams();
  if (filters.targetId) query.set("target_id", filters.targetId);
  if (filters.status) query.set("status", filters.status);
  const suffix = query.toString() ? `?${query}` : "";
  const assessmentQuery = new URLSearchParams(query);
  assessmentQuery.set("offset", String(filters.offset ?? 0));
  assessmentQuery.set("limit", String(assessmentPageSize));
  const [summary, assessments] = await Promise.all([
    redGet(`/api/red/summary${suffix}`, token, isSummary, signal),
    redGet(`/api/red/assessments?${assessmentQuery}`,
      token, value => isPage(value, isAssessment), signal),
  ]);
  return { summary, assessments };
}

async function redPost(
  token: string,
  path: string,
  body: Record<string, string>,
  expectedStatuses: RedCommandReceipt["status"][],
): Promise<RedCommandReceipt> {
  const challenge = await redGet("/api/red/operator/csrf", token,
    (value): value is { csrf_token: string } => isRecord(value) && isText(value.csrf_token));
  const value = await requestJson<unknown>(path, {
    method: "POST",
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "X-Red-CSRF": challenge.csrf_token,
    },
    body: JSON.stringify(body),
  });
  if (!isCommandReceipt(value) || !expectedStatuses.includes(value.status)) {
    throw new ApiRequestError("schema", "Red command response did not match its data contract");
  }
  return value;
}

export function createRedAssessment(token: string, command: {
  requestId: string; targetId: string; mode: "manual" | "autonomous"; approvalId: string;
}): Promise<RedCommandReceipt> {
  return redPost(token, "/api/red/assessments", {
    request_id: command.requestId, target_id: command.targetId,
    mode: command.mode, approval_id: command.approvalId,
  }, ["awaiting_authorization"]);
}

export function authorizeRedAssessment(token: string, assessmentId: string, command: {
  requestId: string; approvalId: string;
}): Promise<RedCommandReceipt> {
  return redPost(token, `/api/red/assessments/${encodeURIComponent(assessmentId)}/authorize`, {
    request_id: command.requestId, approval_id: command.approvalId,
  }, ["queued"]);
}

export function startRedAssessment(
  token: string, assessmentId: string, requestId: string,
): Promise<RedCommandReceipt> {
  return redPost(token, `/api/red/assessments/${encodeURIComponent(assessmentId)}/start`, {
    request_id: requestId,
  }, ["queued"]);
}

export function cancelRedAssessment(
  token: string, assessmentId: string, requestId: string,
): Promise<RedCommandReceipt> {
  return redPost(token, `/api/red/assessments/${encodeURIComponent(assessmentId)}/cancel`, {
    request_id: requestId,
  }, ["cancelled", "cancellation_requested"]);
}

export function runRedStage(token: string, assessmentId: string, stage: string,
  requestId: string): Promise<RedCommandReceipt> {
  return redPost(token,
    `/api/red/assessments/${encodeURIComponent(assessmentId)}/stages/${encodeURIComponent(stage)}/run`,
    { request_id: requestId }, ["queued"]);
}

export async function loadRedWorkspace(token: string, assessmentId: string,
  signal?: AbortSignal): Promise<RedWorkspaceBundle> {
  const root = `/api/red/assessments/${encodeURIComponent(assessmentId)}`;
  const [workspace, events, findings, coverage] = await Promise.all([
    redGet(root, token, isWorkspace, signal),
    redGet(`${root}/events?offset=0&limit=100`, token,
      (value): value is Page<RedEvent> => isPage(value, isEvent), signal),
    redGet(`${root}/findings?offset=0&limit=100`, token,
      isFindingPage, signal),
    redGet(`${root}/coverage`, token, isCoverageBundle, signal),
  ]);
  return { workspace, events: events.items, findings: findings.items,
    findingTotal: findings.pagination.total, coverage };
}

export function loadRedFindingDetail(token: string, findingId: string,
  signal?: AbortSignal): Promise<RedFindingDetail> {
  return redGet(`/api/red/findings/${encodeURIComponent(findingId)}`, token,
    (value): value is RedFindingDetail => isRecord(value) && isFinding(value.finding) &&
      isText(value.operation_id) && isText(value.plan_version) &&
      (value.test_id === null || isText(value.test_id)) &&
      (value.oracle_id === null || isText(value.oracle_id)) &&
      Array.isArray(value.evidence_receipt_ids) && value.evidence_receipt_ids.every(isText) &&
      Array.isArray(value.evidence) && value.evidence.every(item => isRecord(item) &&
        isText(item.evidence_id) && isText(item.receipt_id) &&
        (item.operation_id === null || isText(item.operation_id)) &&
        typeof item.sha256 === "string" && /^[a-f0-9]{64}$/.test(item.sha256) &&
        isText(item.content_type)), signal);
}
