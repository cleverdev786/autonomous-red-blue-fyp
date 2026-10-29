import { useEffect, useState } from "react";
import { ApiRequestError } from "../api";
import {
  authorizeRedAssessment,
  cancelRedAssessment,
  createRedAssessment,
  startRedAssessment,
  type RedAssessment,
  type RedTarget,
} from "./api";
import { loadRememberedRedMode, rememberRedMode, type RedMode } from "./modePreference";
import { NewAssessmentView, type NewAssessmentPhase } from "./NewAssessmentView";

type CommandIntent = { requestId: string; approvalId?: string };

export function NewAssessment({ token, targets, assessments, onChanged }: {
  token: string;
  targets: RedTarget[];
  assessments: RedAssessment[];
  onChanged: () => void;
}) {
  const [targetId, setTargetId] = useState("");
  const [mode, setMode] = useState<RedMode>(loadRememberedRedMode);
  const [phase, setPhase] = useState<NewAssessmentPhase>("setup");
  const [assessmentId, setAssessmentId] = useState<string | null>(null);
  const [draft, setDraft] = useState<CommandIntent | null>(null);
  const [authorizeId, setAuthorizeId] = useState<string | null>(null);
  const [startId, setStartId] = useState<string | null>(null);
  const [cancelId, setCancelId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (phase !== "setup") return;
    const active = assessments.find(item =>
      ["awaiting_authorization", "queued", "running"].includes(item.status));
    if (!active) return;
    setAssessmentId(active.assessment_id);
    setTargetId(active.target_id);
    setMode(active.mode);
    setPhase("recovered");
  }, [assessments, phase]);

  useEffect(() => {
    if (phase !== "cancellation_pending" || !assessmentId) return;
    if (assessments.find(item => item.assessment_id === assessmentId)?.status === "cancelled") {
      setPhase("cancelled");
    }
  }, [assessmentId, assessments, phase]);

  async function run(command: () => Promise<void>) {
    setBusy(true); setError(null);
    try { await command(); }
    catch (caught) { setError(commandError(caught)); }
    finally { setBusy(false); }
  }

  const reset = () => {
    setPhase("setup"); setAssessmentId(null); setDraft(null); setAuthorizeId(null);
    setStartId(null); setCancelId(null); setError(null);
  };

  return <NewAssessmentView targets={targets} targetId={targetId} mode={mode}
    phase={phase} busy={busy} error={error} assessmentId={assessmentId}
    onTargetChange={value => { setTargetId(value); setError(null); }}
    onModeChange={value => { setMode(value); rememberRedMode(value); setError(null); }}
    onReview={() => { if (targetId) { setPhase("review"); setError(null); } }}
    onCreate={() => void run(async () => {
      const intent = draft ?? {
        requestId: commandId("create"), approvalId: commandId("approval"),
      };
      if (!draft) setDraft(intent);
      const receipt = await createRedAssessment(token, {
        requestId: intent.requestId, targetId, mode, approvalId: intent.approvalId!,
      });
      setAssessmentId(receipt.assessment_id);
      setPhase("awaiting_authorization");
      onChanged();
    })}
    onAuthorize={() => void run(async () => {
      if (!assessmentId || !draft?.approvalId) throw new Error("missing assessment draft");
      const requestId = authorizeId ?? commandId("authorize");
      if (!authorizeId) setAuthorizeId(requestId);
      await authorizeRedAssessment(token, assessmentId, {
        requestId, approvalId: draft.approvalId,
      });
      setPhase("authorized");
      onChanged();
    })}
    onStart={() => void run(async () => {
      if (!assessmentId) throw new Error("missing assessment draft");
      const requestId = startId ?? commandId("start");
      if (!startId) setStartId(requestId);
      await startRedAssessment(token, assessmentId, requestId);
      setPhase("active");
      onChanged();
    })}
    onCancel={() => void run(async () => {
      if (!assessmentId) throw new Error("missing assessment draft");
      const requestId = cancelId ?? commandId("cancel");
      if (!cancelId) setCancelId(requestId);
      const receipt = await cancelRedAssessment(token, assessmentId, requestId);
      setPhase(receipt.status === "cancelled" ? "cancelled" : "cancellation_pending");
      onChanged();
    })}
    onEdit={() => { setPhase("setup"); setError(null); }}
    onReset={reset} />;
}

function commandId(prefix: string): string {
  return `${prefix}-${crypto.randomUUID()}`;
}

function commandError(error: unknown): string {
  if (error instanceof ApiRequestError) {
    if (error.status === 401) return "The operator credential was rejected.";
    if (error.status === 403) return "The local authorization challenge was rejected.";
    if (error.status === 409) return "Authorization was rejected because the persisted scope or state changed.";
    if (error.kind === "timeout") return "The local command timed out; retry uses the same request ID.";
    if (error.kind === "network") return "The local Red service is unreachable; retry uses the same request ID.";
    if (error.kind === "schema") return "The Red service returned an invalid command receipt.";
  }
  return "The assessment command could not be completed.";
}
