import type { RedAssessment } from "./api";

export const historyColumns = [
  { key: "assessment", label: "Assessment", type: "number" },
  { key: "target", label: "Target", type: "string" },
  { key: "mode", label: "Mode", type: "string" },
  { key: "status", label: "Status", type: "string" },
  { key: "coverage", label: "Coverage", type: "number" },
  { key: "stage", label: "Active stage", type: "string" },
] as const;
export type HistoryColumn = typeof historyColumns[number]["key"];
export type HistorySort = { key: HistoryColumn; direction: "asc" | "desc" } | null;
export function activeStage(assessment: RedAssessment): string {
  const active = Object.entries(assessment.stage_statuses).find(([, status]) => status === "queued" || status === "running");
  return active ? active.join(" · ").replaceAll("_", " ") : "None";
}
export function historyValue(item: RedAssessment, key: HistoryColumn): string | number {
  return ({ assessment: item.assessment_number ?? 0, target: item.target_id, mode: item.mode,
    status: item.status.replaceAll("_", " "), coverage: item.coverage.executed / Math.max(1, item.coverage.eligible),
    stage: activeStage(item) })[key];
}
export function compareTableValues(a: string | number, b: string | number, type: "string" | "number" | "date"): number {
  if (type === "number") return Number(a) - Number(b);
  if (type === "date") return (Date.parse(String(a)) || 0) - (Date.parse(String(b)) || 0);
  return String(a).localeCompare(String(b), undefined, { sensitivity: "base", numeric: true });
}
export function sortHistoryRows(items: RedAssessment[], sort: HistorySort): RedAssessment[] {
  if (!sort) return items;
  const type = historyColumns.find(column => column.key === sort.key)!.type;
  return items.map((item, index) => ({ item, index })).sort((a, b) =>
    (sort.direction === "asc" ? 1 : -1) * compareTableValues(historyValue(a.item, sort.key), historyValue(b.item, sort.key), type) || a.index - b.index
  ).map(row => row.item);
}
export function historyPageNumbers(page: number, pages: number): Array<number | "…"> {
  const numbers = [...new Set([1, pages, page - 1, page, page + 1])].filter(n => n >= 1 && n <= pages).sort((a, b) => a - b);
  return numbers.flatMap((number, index) => index && number - numbers[index - 1] > 1 ? ["…" as const, number] : [number]);
}
