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

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000/api";

export async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "GET",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(`Dashboard request failed (${response.status})`);
  }
  return (await response.json()) as T;
}
