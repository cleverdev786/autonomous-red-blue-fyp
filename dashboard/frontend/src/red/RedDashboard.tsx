import { useEffect, useRef, useState } from "react";
import { ApiRequestError } from "../api";
import { deleteRedHistory, listRedTargets, loadRedDashboard, listRedAssessments, readRedSummary, type RedDashboardSummary, type Page, type RedAssessment, type RedTarget } from "./api";
import { NewAssessment } from "./NewAssessment";
import { AssessmentWorkspace } from "./AssessmentWorkspace";
import { RedDashboardView, type RedDashboardState } from "./RedDashboardView";
import { Button } from "../components/ui/button";
import { assessmentPath } from "../routes";
import { notify } from "../ui";
import type { HistorySort } from "./historyTable";

export function RedDashboard({ assessmentId, onNavigate }: {
  assessmentId?: string; onNavigate: (path: string) => void;
}) {
  const token = "";
  const [targets, setTargets] = useState<RedTarget[]>([]);
  const [targetId, setTargetId] = useState("");
  const [status, setStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<HistorySort>(null);
  const manualRefresh = useRef(false);
  useEffect(() => {
    const timer = window.setTimeout(() => setQuery(search.trim()), 150);
    return () => window.clearTimeout(timer);
  }, [search]);
  const [refresh, setRefresh] = useState(0);
  const [summary, setSummary] = useState<RedDashboardSummary | null>(null);
  const [history, setHistory] = useState<{page: Page<RedAssessment>; query: string} | null>(null);
  const state: RedDashboardState = summary && history ? { kind:"ready", summary, assessments:history.page.items,
    ...history.page.pagination } : {kind:"loading"};
  const [showSetup, setShowSetup] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [readError, setReadError] = useState<string | null>(null);
  const focusHistory = useRef(false);
  useEffect(() => {
    if (state.kind === "ready" && focusHistory.current) {
      document.getElementById("red-history-title")?.focus();
      focusHistory.current = false;
    }
  }, [state]);
  const openAssessment = (id: string) => { setShowSetup(false); onNavigate(assessmentPath(id)); };

  useEffect(() => {
    const controller = new AbortController();
    setRefreshing(true); setReadError(null);
    void Promise.all([listRedTargets(token, controller.signal), readRedSummary(token, {targetId, status}, controller.signal)])
      .then(([page, data]) => {
        if (controller.signal.aborted) return;
        setTargets(page.items); setSummary(data);
        if (manualRefresh.current) { notify("Red dashboard refreshed."); manualRefresh.current = false; }
      }).catch(error => {
        if (controller.signal.aborted || error instanceof ApiRequestError && error.kind === "aborted") return;
        setReadError("Dashboard data could not refresh. Displayed values may be out of date; refresh to retry.");
        manualRefresh.current = false;
      }).finally(() => { if (!controller.signal.aborted) setRefreshing(false); });
    return () => controller.abort();
  }, [token, targetId, status, refresh]);

  useEffect(() => {
    const controller = new AbortController();
    setHistoryLoading(true); setReadError(null);
    void listRedAssessments(token, {targetId, status, offset, limit:pageSize, query, sort}, controller.signal)
      .then(page => {
        if (controller.signal.aborted) return;
        setHistory({page, query});
      }).catch(error => {
        if (controller.signal.aborted || error instanceof ApiRequestError && error.kind === "aborted") return;
        setReadError("Assessment history could not update. Displayed rows may be out of date; refresh to retry.");
      }).finally(() => { if (!controller.signal.aborted) setHistoryLoading(false); });
    return () => controller.abort();
  }, [token, targetId, status, offset, refresh, pageSize, query, sort]);

  if (assessmentId) return <div className="red-workspace mars-content">
    <AssessmentWorkspace key={assessmentId} token={token} assessmentId={assessmentId}
      onClose={() => onNavigate("/dashboard/red-team")}
      onChanged={() => setRefresh(value => value + 1)} />
  </div>;

  return <div className="red-workspace">
    <div className="mars-content flex flex-wrap items-center justify-between gap-4">
      <p className="text-muted-foreground">Review saved assessments or begin a scoped workflow.</p>
      <Button className="new-assessment-button" onClick={() => setShowSetup(value => !value)} aria-expanded={showSetup} aria-controls="red-setup">
        {showSetup ? "Close setup" : "New assessment"}
      </Button>
    </div>
    {showSetup && <div id="red-setup" className="mars-content"><NewAssessment token={token} targets={targets}
      assessments={state.kind === "ready" ? state.assessments : []}
      onOpened={openAssessment}
      onChanged={() => setRefresh(value => value + 1)} /></div>}
    <RedDashboardView targets={targets} targetId={targetId} status={status}
      state={state.kind === "loading" && readError ? {kind:"error",message:readError} : state} refreshing={refreshing} historyLoading={historyLoading} readError={readError} onTargetChange={value => { setTargetId(value); setOffset(0); }}
      onStatusChange={value => { setStatus(value); setOffset(0); }}
      onRefresh={() => { manualRefresh.current = true; setRefresh(value => value + 1); }} onPageChange={setOffset}
      search={search} query={history?.query ?? ""} onSearchChange={setSearch} sort={sort} onSortChange={setSort}
      onPageSizeChange={value => { setPageSize(value); setOffset(0); }}
      onDelete={async ids => {
        await deleteRedHistory(token, ids);
        setReadError(null);
        try {
          let dashboard = await loadRedDashboard(token, { targetId, status, offset, limit: pageSize, query, sort });
          const nextOffset = dashboard.assessments.pagination.total === 0 ? 0 : Math.min(offset,
            Math.floor((dashboard.assessments.pagination.total - 1) / dashboard.assessments.pagination.limit) * dashboard.assessments.pagination.limit);
          if (nextOffset !== offset) dashboard = await loadRedDashboard(token, { targetId, status, offset: nextOffset, limit: pageSize, query, sort });
          setSummary(dashboard.summary); setHistory({page:dashboard.assessments, query});
          if (nextOffset !== offset) setOffset(nextOffset);
        } catch {
          setHistory(current => current ? {...current, page:{...current.page,
            items:current.page.items.filter(item => !ids.includes(item.assessment_id)),
            pagination:{...current.page.pagination,total:Math.max(0,current.page.pagination.total-ids.length)}}} : current);
          setReadError("History was deleted, but updated totals could not load. Refresh to retry.");
        }
        focusHistory.current = true;
        notify(`${ids.length} history record${ids.length === 1 ? "" : "s"} deleted.`);
      }}
      onInspect={openAssessment} />
  </div>;
}
