import { useEffect, useRef, useState } from "react";
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
import { notify } from "../ui";

type CommandIntent = { requestId: string; approvalId?: string };

export function NewAssessment({ token, targets, assessments, onChanged, onOpened }: {
  token: string;
  targets: RedTarget[];
  assessments: RedAssessment[];
  onChanged: () => void;
  onOpened?: (id: string) => void;
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
  const pending = useRef(false);

  useEffect(() => {
    if (phase !== "cancellation_pending" || !assessmentId) return;
    if (assessments.find(item => item.assessment_id === assessmentId)?.status === "cancelled") {
      setPhase("cancelled");
    }
  }, [assessmentId, assessments, phase]);

  async function run(command: () => Promise<void>) {
    if (pending.current) return;
    pending.current = true;
    setBusy(true); setError(null);
    try { await command(); notify("Assessment command accepted."); }
    catch (caught) { setError(commandError(caught)); notify("Assessment command was not accepted.", true); }
    finally { pending.current = false; setBusy(false); }
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
      if (mode === "autonomous") {
        const nextStartId = startId ?? commandId("start");
        if (!startId) setStartId(nextStartId);
        await startRedAssessment(token, assessmentId, nextStartId);
        setPhase("active");
      } else {
        setPhase("authorized");
      }
      onChanged();
      onOpened?.(assessmentId);
    })}
    onStart={() => void run(async () => {
      if (!assessmentId) throw new Error("missing assessment draft");
      const requestId = startId ?? commandId("start");
      if (!startId) setStartId(requestId);
      await startRedAssessment(token, assessmentId, requestId);
      setPhase("active");
      onChanged();
      onOpened?.(assessmentId);
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
    if (error.status === 403) return "The local origin or CSRF authorization was rejected.";
    if (error.status === 409) return "Authorization was rejected because the persisted scope or state changed.";
    if (error.kind === "timeout") return "The local command timed out; retry uses the same request ID.";
    if (error.kind === "network") return "The local Red service is unreachable; retry uses the same request ID.";
    if (error.kind === "schema") return "The Red service returned an invalid command receipt.";
  }
  return "The assessment command could not be completed.";
}
