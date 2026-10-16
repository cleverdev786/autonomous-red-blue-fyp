import type { ButtonHTMLAttributes, ReactNode } from "react";

export type NoticeTone = "information" | "warning" | "danger" | "success";

/** Visual feedback only. No operation or evidence is deemed verified by a component. */
export function Notice({ title, tone = "information", children }: {
  title: string; tone?: NoticeTone; children?: ReactNode;
}) {
  return <div className={"ui-notice ui-notice--" + tone} role={tone === "danger" ? "alert" : "status"}>
    <strong>{title}</strong>
    {children && <div className="ui-notice__detail">{children}</div>}
  </div>;
}

export function EmptyState({ title, description }: { title: string; description: string }) {
  return <div className="ui-empty" role="status">
    <strong>{title}</strong>
    <p>{description}</p>
  </div>;
}

export function LoadingState({ label }: { label: string }) {
  return <div className="ui-loading" role="status" aria-live="polite">
    <span className="ui-loading__marker" aria-hidden="true" />
    {label}
  </div>;
}

export function ActionButton({ variant = "primary", className = "", type = "button", ...props }:
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" }) {
  return <button {...props} type={type} className={["ui-button", "ui-button--" + variant, className].filter(Boolean).join(" ")} />;
}
