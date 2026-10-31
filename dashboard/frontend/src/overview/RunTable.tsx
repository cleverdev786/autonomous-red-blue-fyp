import type { RunItem } from "../api";
import { EmptyState } from "../ui";

function score(value: string | number | null): string {
  return value === null ? "—" : String(value);
}

export function RunTable({ runs, onSelect, selectedRunId }: {
  runs: RunItem[];
  onSelect?: (id: string) => void;
  selectedRunId?: string;
}) {
  return <div className="table-wrap">
    <table>
      <thead><tr><th>Run</th><th>RQ</th><th>Status</th><th>Red</th><th>Blue</th><th>Subject</th></tr></thead>
      <tbody>
        {runs.length === 0 && <tr><td colSpan={6}><EmptyState title="No stored runs here"
          description="This local database has no stored run records. This is not a statement about final research or external archives." /></td></tr>}
        {runs.map(run => <tr key={run.run_id}>
          <td>{onSelect ? <button type="button" className="table-link" aria-current={selectedRunId === run.run_id ? "true" : undefined} onClick={() => onSelect(run.run_id)}
            aria-label={"View stored run " + run.run_id}>{run.run_id}</button> : run.run_id}</td>
          <td>{run.research_question}</td>
          <td><span className={"status " + run.status}>{run.status}</span></td>
          <td>{score(run.red_score)}</td><td>{score(run.blue_score)}</td>
          <td>{run.scenario_id ?? run.dataset_id}</td>
        </tr>)}
      </tbody>
    </table>
  </div>;
}
