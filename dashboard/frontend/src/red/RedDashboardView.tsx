import { Fragment, useEffect, useRef, useState, type ReactNode } from "react";
import { ActionButton, LoadingState, Notice, notify } from "../ui";
import { ApiRequestError } from "../api";
import { Dialog, DialogContent, DialogTitle, DialogDescription } from "../components/ui/dialog";
import { Button } from "../components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { assessmentPath } from "../routes";
import {
  assessmentStatuses,
  assessmentLabel,
  type RedAssessment,
  type RedDashboardSummary,
  type RedTarget,
} from "./api";

import { Search, X, ChevronUp, ChevronLeft, ChevronRight } from "lucide-react";
import { activeStage, historyColumns, historyPageNumbers, sortHistoryRows, type HistorySort } from "./historyTable";

type TableControls = {
  search?: string; query?: string; onSearchChange?: (value: string) => void;
  sort?: HistorySort; onSortChange?: (value: HistorySort) => void;
  onPageSizeChange?: (value: number) => void;
};

export type RedDashboardState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; summary: RedDashboardSummary; assessments: RedAssessment[];
      total: number; offset: number; limit: number };

const label = (value: string) => value.replaceAll("_", " ");

export function RedDashboardView({ targets, targetId, status, state, onTargetChange,
  onStatusChange, onRefresh, onPageChange, onInspect, onDelete, refreshing = false, historyLoading = false, readError, ...tableControls }: TableControls & {
  targets: RedTarget[];
  targetId: string;
  status: string;
  state: RedDashboardState;
  onTargetChange: (value: string) => void;
  onStatusChange: (value: string) => void;
  onRefresh: () => void;
  onPageChange: (offset: number) => void;
  onInspect: (assessmentId: string) => void;
  onDelete?: (assessmentIds: string[]) => Promise<void>;
  refreshing?: boolean;
  historyLoading?: boolean;
  readError?: string | null;
}) {
  const filters = <section className="red-dashboard-toolbar" aria-label="Red dashboard filters">
      <div className="filter-field"><label id="target-filter-label">Target</label>
        <Select value={targetId || "all"} onValueChange={value => onTargetChange(value === "all" ? "" : value)}>
          <SelectTrigger aria-labelledby="target-filter-label"><SelectValue>{targetId || "All Targets"}</SelectValue></SelectTrigger>
          <SelectContent position="popper" align="start"><SelectItem value="all">All Targets</SelectItem>
            {targets.map(target => <SelectItem key={target.target_id} value={target.target_id}>{target.target_id}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>
      <div className="filter-field"><label id="status-filter-label">Assessment status</label>
        <Select value={status || "all"} onValueChange={value => onStatusChange(value === "all" ? "" : value)}>
          <SelectTrigger aria-labelledby="status-filter-label"><SelectValue>{status ? label(status) : "All statuses"}</SelectValue></SelectTrigger>
          <SelectContent position="popper" align="start"><SelectItem value="all">All statuses</SelectItem>
            {assessmentStatuses.map(item => <SelectItem key={item} value={item}>{label(item)}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>
      <ActionButton variant="secondary" disabled={refreshing || state.kind === "loading"} onClick={onRefresh}>
        {refreshing || state.kind === "loading" ? "Refreshing…" : "Refresh"}</ActionButton>
    </section>;
  return <div className="mars-content red-dashboard">
    {state.kind !== "ready" && filters}

    {state.kind === "loading" && <section className="surface-card red-dashboard-state" aria-busy="true">
      <LoadingState label="Loading Red assessment data…" />
    </section>}
    {state.kind === "error" && <Notice title="Red dashboard unavailable" tone="danger">
      {state.message} Check the local Red service, then refresh.
    </Notice>}
    {readError && state.kind === "ready" && <Notice title="History refresh incomplete" tone="warning">{readError}</Notice>}
    {state.kind === "ready" && <ReadyDashboard summary={state.summary}
      assessments={state.assessments} total={state.total} offset={state.offset}
      limit={state.limit} onPageChange={onPageChange} onInspect={onInspect} onDelete={onDelete} refreshing={historyLoading || refreshing} filters={filters} {...tableControls} />}
  </div>;
}

function ReadyDashboard({ summary, assessments, total, offset, limit, onPageChange, onInspect, onDelete, refreshing, search = "", query = "", sort = null, onSearchChange, onSortChange, onPageSizeChange, filters }: TableControls & {
  summary: RedDashboardSummary;
  assessments: RedAssessment[];
  total: number;
  offset: number;
  limit: number;
  onPageChange: (offset: number) => void;
  onInspect: (assessmentId: string) => void;
  onDelete?: (assessmentIds: string[]) => Promise<void>;
  refreshing: boolean;
  filters?: ReactNode;
}) {
  const searchInput = useRef<HTMLInputElement>(null);
  const [scrolled, setScrolled] = useState(false);
  const rows = sortHistoryRows(assessments, sort);
  const [selected, setSelected] = useState<string[]>([]);
  const [confirming, setConfirming] = useState<string[] | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const pending = useRef(false);
  const cancelButton = useRef<HTMLButtonElement>(null);
  const deleteTrigger = useRef<HTMLElement | null>(null);
  const deletable = assessments.filter(canDeleteHistory).map(item => item.assessment_id);
  const allSelected = deletable.length > 0 && deletable.every(id => selected.includes(id));
  useEffect(() => {
    if (!pending.current) { setSelected([]); setConfirming(null); }
  }, [assessments]);
  const confirm = (ids: string[]) => {
    deleteTrigger.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setDeleteError(null); setConfirming(ids);
  };
  async function remove() {
    if (pending.current || !confirming || !onDelete) return;
    pending.current = true; setDeleting(true); setDeleteError(null);
    try { await onDelete(confirming); setSelected([]); setConfirming(null); }
    catch (error) {
      const message = error instanceof ApiRequestError && error.status === 401
        ? "Your session expired. Reload and sign in again before deleting history."
        : error instanceof ApiRequestError && error.status === 409
        ? "Records changed or still have active work. Cancel and refresh the list before retrying."
        : "History could not be deleted. Your selection is kept; try again.";
      setDeleteError(message); notify(message, true);
    } finally { pending.current = false; setDeleting(false); }
  }
  const metrics = [
    { label: "Verified findings", value: summary.confirmed_findings,
      detail: `${summary.confirmed_findings} confirmed · ${summary.suspected_findings} suspected` },
    { label: "Endpoint coverage", value: `${summary.tested} / ${summary.eligible}`,
      detail: `${summary.coverage_gaps} open coverage gaps` },
    { label: "Active assessments", value: summary.active_assessments,
      detail: `${summary.queued_assessments} queued` },
    { label: "Agent activity", value: summary.active_stages,
      detail: `${summary.active_stages} queued or running stages` },
  ];
  return <>
    <p className="text-sm text-muted-foreground">Totals span assessments in history and can include repeated findings. Workflow completion does not establish target safety.</p>
    {assessments.find(item => ["queued", "running", "awaiting_authorization"].includes(item.status)) &&
      <section className="surface-card p-4"><h2>Continue an assessment</h2>
        {assessments.filter(item => ["queued", "running", "awaiting_authorization"].includes(item.status)).map(item =>
          <Button key={item.assessment_id} variant="outline" asChild><a href={assessmentPath(item.assessment_id)}
            onClick={event => { if (event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) {
              event.preventDefault(); onInspect(item.assessment_id);
            } }}>{item.target_id} · {label(item.status)}</a></Button>)}
      </section>}
    <section className="red-metrics" aria-label="Red Team metrics">
      {metrics.map(metric => <article className="red-metric" key={metric.label}>
        <span>{metric.label}</span><strong>{metric.value}</strong><small>{metric.detail}</small>
      </article>)}
    </section>
    <section className="surface-card red-history" aria-labelledby="red-history-title">
      <div className="red-history-head">
        <div><h2 id="red-history-title" tabIndex={-1}>Assessment history</h2>
          <p>Server-authoritative Red assessments matching the selected filters.</p></div>

      </div>
      {filters}
      {onDelete && selected.length > 0 && <div className="history-selection-toolbar flex justify-end gap-3 mb-3">
        <Button variant="outline" className="history-delete-action" disabled={deleting || refreshing}
          onClick={() => confirm(selected)}>{selected.length === 1 ? "Delete selected record" : `Delete ${selected.length} selected records`}</Button>
      </div>}
      <div className="history-toolbar flex flex-wrap items-center justify-between gap-3 mb-4">
        <div className="history-search relative w-full max-w-sm">
          <Search size={15} aria-hidden="true" className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input ref={searchInput} type="search" aria-label="Search assessment history" placeholder="Search assessments, targets, status…"
            maxLength={200} value={search} onChange={event => onSearchChange?.(event.target.value)}
            className="w-full rounded-lg border border-border bg-card py-2.5 pl-9 pr-10 text-[13px] text-foreground" />
          {search && <button type="button" aria-label="Clear search" onClick={() => { onSearchChange?.(""); searchInput.current?.focus(); }}
            className="absolute right-1 top-1/2 -translate-y-1/2 p-2 text-muted-foreground hover:text-foreground"><X size={16} /></button>}
        </div>
        <p className="history-result-count text-xs text-muted-foreground" role="status" aria-live="polite" aria-atomic="true">
          <span className="history-loading-indicator" aria-hidden="true">{refreshing ? "Updating…" : ""}</span>
          Showing {total && assessments.length ? offset + 1 : 0}–{Math.min(offset + assessments.length, total)} of {total}
        </p>
      </div>
      <div className={`table-wrap history-scroll ${scrolled ? "is-scrolled" : ""}`} role="region" aria-label="Assessment history table" aria-busy={refreshing} tabIndex={0}
        onScroll={event => setScrolled(event.currentTarget.scrollTop > 0)}><table>
          <thead><tr>{onDelete && <th scope="col"><input type="checkbox" aria-label="Select all deletable records on this page"
            checked={allSelected} disabled={!deletable.length || deleting || refreshing}
            ref={node => { if (node) node.indeterminate = selected.length > 0 && !allSelected; }}
            onChange={event => setSelected(event.target.checked ? deletable : [])} /></th>}
            {historyColumns.map(column => {
              const active = sort?.key === column.key;
              const change = () => onSortChange?.(!active ? {key: column.key, direction: "asc"} :
                sort.direction === "asc" ? {key: column.key, direction: "desc"} : null);
              return <th key={column.key} scope="col" tabIndex={0}
                aria-sort={active ? sort.direction === "asc" ? "ascending" : "descending" : "none"}
                onClick={change} onKeyDown={event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); change(); } }}>
                {column.label}<ChevronUp aria-hidden="true" size={12} className={`history-sort-caret ${active ? "is-active" : ""} ${active && sort.direction === "desc" ? "is-descending" : ""}`} />
              </th>;
            })}<th scope="col"><span className="sr-only">Open</span></th></tr></thead>
          <tbody>{rows.length === 0 ? <tr><td colSpan={onDelete ? 8 : 7} className="history-empty">
            {query ? <>No results match “{query}”.</> : "No assessments match the selected filters."}
          </td></tr> : rows.map(item => <tr key={item.assessment_id}>
            {onDelete && <td><input type="checkbox" aria-label={`Select ${assessmentLabel(item)}`}
              checked={selected.includes(item.assessment_id)} disabled={!canDeleteHistory(item) || deleting || refreshing}
              onChange={event => setSelected(current => event.target.checked ? [...current, item.assessment_id] : current.filter(id => id !== item.assessment_id))} /></td>}
            <td><span className="assessment-number" title={item.assessment_id}><Match text={assessmentLabel(item)} query={query} /></span>
              <small className="record-caption"><Match text={`${label(item.profile)} profile`} query={query} /></small></td>
            <td><Match text={item.target_id} query={query} /></td><td><Match text={item.mode} query={query} /></td>
            <td><span className={`red-status red-status--${item.status}`}><span className="history-status-dot" aria-hidden="true" /><span><Match text={label(item.status).replace(/^./, character => character.toUpperCase())} query={query} /></span></span></td>
            <td><Match text={`${item.coverage.executed} / ${item.coverage.eligible}`} query={query} />
              <progress aria-label={"Executed tests for " + assessmentLabel(item)}
                value={item.coverage.executed} max={Math.max(1, item.coverage.eligible)} /></td>
            <td><Match text={activeStage(item)} query={query} /></td><td><Button variant="outline" asChild>
              <a href={assessmentPath(item.assessment_id)} aria-label={"Open workspace for " + assessmentLabel(item)}
                onClick={event => { if (event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) {
                  event.preventDefault(); onInspect(item.assessment_id);
                } }}>Open workspace</a></Button></td>
          </tr>)}</tbody>
        </table></div>
      <HistoryPages total={total} offset={offset} limit={limit} busy={refreshing || deleting}
        onPageChange={onPageChange} onPageSizeChange={onPageSizeChange} />
    </section>
    <Dialog open={confirming !== null} onOpenChange={open => { if (!open && !deleting) setConfirming(null); }}>
      <DialogContent className="evidence-dialog history-delete-dialog" aria-busy={deleting}
        onOpenAutoFocus={event => { event.preventDefault(); cancelButton.current?.focus(); }}
        onCloseAutoFocus={event => {
          event.preventDefault();
          const trigger = deleteTrigger.current;
          if (trigger?.isConnected && !trigger.matches(":disabled")) trigger.focus();
          else document.getElementById("red-history-title")?.focus();
        }}>
        <DialogTitle>Delete {confirming?.length === 1 ? "history record" : `${confirming?.length ?? 0} history records`}?</DialogTitle>
        <DialogDescription>{confirming?.length ?? 0} selected on this page. Delete only the records listed below. Stop active assessments before deleting their history. Stored evidence and audit links are kept.</DialogDescription>
        <ul className="history-delete-list" aria-label="Selected history records">{confirming?.map(id => {
          const item = assessments.find(item => item.assessment_id === id);
          return <li key={id}>{item ? `${assessmentLabel(item)} · ${item.target_id}` : "Selected record"}</li>;
        })}</ul>
        {deleting && <div role="status" aria-live="polite"><LoadingState label="Deleting selected records and updating history…" /></div>}
        {deleteError && <Notice title="Deletion failed" tone="danger">{deleteError}</Notice>}
        <div className="red-workspace-actions">
          <Button variant="outline" asChild><button type="button" ref={cancelButton} disabled={deleting} onClick={() => setConfirming(null)}>Cancel</button></Button>
          <Button variant="outline" className="history-delete-action" disabled={deleting} onClick={() => void remove()}>{deleting ? "Deleting…" : "Delete history"}</Button>
        </div>
      </DialogContent>
    </Dialog>
  </>;
}

function Match({ text, query }: { text: string; query: string }) {
  if (!query) return <>{text}</>;
  const lower = text.toLowerCase(), needle = query.toLowerCase();
  const parts = []; let cursor = 0, index = lower.indexOf(needle);
  while (index !== -1) {
    parts.push(<Fragment key={index}>{text.slice(cursor, index)}<mark>{text.slice(index, index + query.length)}</mark></Fragment>);
    cursor = index + query.length; index = lower.indexOf(needle, cursor);
  }
  return <>{parts}{text.slice(cursor)}</>;
}

function HistoryPages({ total, offset, limit, busy, onPageChange, onPageSizeChange }: {
  total: number; offset: number; limit: number; busy: boolean; onPageChange: (offset: number) => void;
  onPageSizeChange?: (value: number) => void;
}) {
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));
  return <div className="history-pagination flex flex-wrap items-center justify-between gap-4 mt-4">
    <label className="flex items-center gap-3 text-xs text-muted-foreground">Rows per page
      <Select value={String(limit)} disabled={busy} onValueChange={value => onPageSizeChange?.(Number(value))}>
        <SelectTrigger aria-label="Rows per page"><SelectValue /></SelectTrigger>
        <SelectContent>{[10,25,50].map(size => <SelectItem key={size} value={String(size)}>{size}</SelectItem>)}</SelectContent>
      </Select>
    </label>
    <nav className="history-page-nav" aria-label="Assessment history pages">
      <Button variant="outline" size="icon" aria-label="Previous page" disabled={busy || page === 1} onClick={() => onPageChange(offset - limit)}><ChevronLeft size={16} /></Button>
      {historyPageNumbers(page, pages).map((number, index) => number === "…" ? <span key={`gap-${index}`} className="px-2" aria-hidden="true">…</span> :
        <Button key={number} variant="outline" className="history-page-number" aria-label={`Page ${number}`} aria-current={number === page ? "page" : undefined}
          disabled={busy} onClick={() => onPageChange((number - 1) * limit)}>{number}</Button>)}
      <Button variant="outline" size="icon" aria-label="Next page" disabled={busy || page >= pages} onClick={() => onPageChange(offset + limit)}><ChevronRight size={16} /></Button>
    </nav>
  </div>;
}

export function canDeleteHistory(assessment: RedAssessment): boolean {
  return ["completed", "completed_with_limitations", "failed", "cancelled", "blocked"].includes(assessment.status) &&
    !Object.values(assessment.stage_statuses).some(status => status === "queued" || status === "running");
}
