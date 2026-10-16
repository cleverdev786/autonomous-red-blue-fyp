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

async function requestJson<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    method: "GET",
    headers: { Accept: "application/json" },
    ...options,
  });
  if (!response.ok) {
    throw new Error(`Dashboard request failed (${response.status})`);
  }
  return (await response.json()) as T;
}

export function getJson<T>(path: string): Promise<T> {
  return requestJson<T>(`${API_BASE}${path}`);
}

// Always use the pinned read-only console origin through the local Vite proxy.
export function getConsoleJson<T>(path: string): Promise<T> {
  return requestJson<T>(`/api/console${path}`);
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
