/** Local-only MARS navigation. No remote or security actions originate here. */
export const BASE_PATH = "/dashboard";

export type View =
  | "Overview" | "Runs" | "Run Detail" | "Findings" | "Patch Verification"
  | "Metrics" | "Audit" | "Development Evidence" | "Trusted Preview" | "Operator Status";
export type Section = "Overview" | "Assessments" | "Findings" | "Remediation" | "Reports" | "System";
export type Route = { path: string; title: string; section: Section | null; view: View | null; notFound?: boolean };

export const primaryRoutes: Route[] = [
  { path: `${BASE_PATH}/`, title: "Overview", section: "Overview", view: "Overview" },
  { path: `${BASE_PATH}/assessments`, title: "Assessments", section: "Assessments", view: null },
  { path: `${BASE_PATH}/findings`, title: "Findings", section: "Findings", view: "Findings" },
  { path: `${BASE_PATH}/remediation`, title: "Remediation", section: "Remediation", view: "Trusted Preview" },
  { path: `${BASE_PATH}/reports`, title: "Reports", section: "Reports", view: "Runs" },
  { path: `${BASE_PATH}/system`, title: "System", section: "System", view: "Operator Status" },
];

const secondaryRoutes: Route[] = [
  { path: `${BASE_PATH}/reports/runs`, title: "Stored runs", section: "Reports", view: "Runs" },
  { path: `${BASE_PATH}/reports/run-detail`, title: "Run detail", section: "Reports", view: "Run Detail" },
  { path: `${BASE_PATH}/reports/development-evidence`, title: "Development evidence", section: "Reports", view: "Development Evidence" },
  { path: `${BASE_PATH}/reports/metrics`, title: "Research metrics", section: "Reports", view: "Metrics" },
  { path: `${BASE_PATH}/reports/audit`, title: "Audit", section: "Reports", view: "Audit" },
  { path: `${BASE_PATH}/remediation/patch-verification`, title: "Patch verification", section: "Remediation", view: "Patch Verification" },
];

const allRoutes = [...primaryRoutes, ...secondaryRoutes];

export function resolveRoute(pathname: string): Route {
  // Remove trailing slashes except on the mount root; keep unknown paths unknown.
  const path = pathname.replace(/\/+$/, "") || "/";
  const canonical = path === BASE_PATH ? `${BASE_PATH}/` : path;
  return allRoutes.find((route) => route.path === canonical) ?? {
    path: canonical, title: "Page not found", section: null, view: null, notFound: true,
  };
}
