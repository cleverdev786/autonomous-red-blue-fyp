import type { LocalModelSession } from "../api";

/** Displays only backend-verified local model identity. No inferred model names. */
export function ModelStatus({ active }: { active: LocalModelSession }) {
  const hasSession = active.state !== "unloaded";
  const running = active.state === "running" || active.state === "starting";
  return <>
    <div>
      <dt>Currently loaded model</dt>
      <dd>{hasSession && running ? active.filename :
        hasSession ? "No model running" : "No model loaded"}</dd>
      <small>{active.state === "stopped"
        ? "Last session: " + active.filename
        : "Exact GGUF file reported by the local model manager"}</small>
    </div>
    <div>
      <dt>Model status</dt>
      <dd><span className={active.state === "running" ? "status accepted" : "status"}>
        {active.state}
      </span></dd>
      <small>{active.state === "running" ? "Local model inference server is reachable"
        : active.state === "starting" ? "Model startup is in progress"
        : active.state === "stopped" ? "Model process stopped unexpectedly"
        : "No local model process is loaded"}</small>
    </div>
    <div>
      <dt>Model identifier</dt>
      <dd className="model-identity">{hasSession ? active.model_name : "None"}</dd>
      <small>Local runtime alias</small>
    </div>
    <div>
      <dt>GGUF SHA-256</dt>
      <dd className="model-fingerprint">{hasSession ? active.sha256 : "Not applicable"}</dd>
      <small>{hasSession ? "Fingerprint verified by the loader" : "No model fingerprint available"}</small>
    </div>
    {hasSession && <div>
      <dt>Local inference endpoint</dt>
      <dd>127.0.0.1:{active.port}</dd>
      <small>{active.context_tokens} context tokens · {active.concurrency} concurrent session</small>
    </div>}
    <div>
      <dt>Model research status</dt>
      <dd className="model-identity">{active.final_research_ready ? "Reported ready; review required"
        : "Not research-qualified"}</dd>
      <small>Runtime readiness does not establish independent research qualification</small>
    </div>
  </>;
}
