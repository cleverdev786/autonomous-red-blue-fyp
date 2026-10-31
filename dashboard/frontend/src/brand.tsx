import type { SVGProps } from "react";

type NavName = "Overview" | "Red Team" | "Blue Team" | "Assessments" | "Findings" | "Remediation" | "Reports" | "System";

const icons: Record<NavName, string> = {
  Overview: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
  "Red Team": "M12 3 3 7v5c0 5 3 7 9 9 6-2 9-4 9-9V7z M9 12l6-3 M9 12l6 3",
  "Blue Team": "M12 3 3 7v5c0 5 3 7 9 9 6-2 9-4 9-9V7z M8 12l3 3 5-6",
  Assessments: "M4 3h12l4 4v14H4z M16 3v5h5 M8 12h8 M8 16h6",
  Findings: "M12 3 3 7v5c0 5 3 7 9 9 6-2 9-4 9-9V7z M12 8v5 M12 17h.01",
  Remediation: "M14 5a5 5 0 0 0-6 6l-5 5 5 5 5-5a5 5 0 0 0 6-6z M15 9l4-4 2 2-4 4",
  Reports: "M5 3h10l4 4v14H5z M15 3v5h4 M8 17v-4 M12 17V9 M16 17v-6",
  System: "M12 3v3 M12 18v3 M3 12h3 M18 12h3 M5.6 5.6l2.1 2.1 M16.3 16.3l2.1 2.1 M18.4 5.6l-2.1 2.1 M7.7 16.3l-2.1 2.1 M12 9a3 3 0 1 0 0 6a3 3 0 0 0 0-6",
};

export function NavIcon({ name, ...props }: { name: NavName } & SVGProps<SVGSVGElement>) {
  return <svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor"
    strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>
    <path d={icons[name]} />
  </svg>;
}

export function MarsMark({ className = "" }: { className?: string }) {
  return <svg className={className} viewBox="0 0 44 44" aria-hidden="true" fill="none">
    <rect width="44" height="44" rx="11" fill="#1D5BBD" />
    <path d="M10.5 31V13.5L22 25L33.5 13.5V31" stroke="white"
      strokeWidth="4.2" strokeLinejoin="round" strokeLinecap="round" />
    <circle cx="34" cy="10" r="2.2" fill="#C5E6FF" />
  </svg>;
}
