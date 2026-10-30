import { useEffect, useState, type ComponentProps, type ReactNode } from "react";
import { Button } from "./components/ui/button";

export type NoticeTone = "information" | "warning" | "danger" | "success";
type Toast = { id: number; message: string; error: boolean };
export function notify(message: string, error = false) {
  if (typeof window !== "undefined" && typeof window.dispatchEvent === "function")
    window.dispatchEvent(new CustomEvent("mars-notification", { detail: { message, error } }));
}
export function NotificationCenter() {
  const [items, setItems] = useState<Toast[]>([]);
  useEffect(() => {
    let id = 0;
    const timers = new Set<ReturnType<typeof setTimeout>>();
    const receive = (event: Event) => {
      const detail = (event as CustomEvent<{ message: string; error: boolean }>).detail;
      const item = { ...detail, id: ++id };
      setItems(current => [...current.slice(-2), item]);
      const timer = setTimeout(() => { setItems(current => current.filter(value => value.id !== item.id)); timers.delete(timer); }, 6000);
      timers.add(timer);
    };
    window.addEventListener("mars-notification", receive);
    return () => { window.removeEventListener("mars-notification", receive); timers.forEach(clearTimeout); };
  }, []);
  return <aside className="notification-center" aria-label="Notifications">{items.map(item =>
    <div className="notification" key={item.id} role={item.error ? "alert" : "status"}>
      <span>{item.message}</span><button type="button" aria-label="Dismiss notification"
        onClick={() => setItems(current => current.filter(value => value.id !== item.id))}>×</button>
    </div>)}</aside>;
}

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
  Omit<ComponentProps<typeof Button>, "variant"> & { variant?: "primary" | "secondary" }) {
  return <Button {...props} type={type} variant={variant === "primary" ? "default" : "secondary"}
    className={["ui-button", "ui-button--" + variant, className].filter(Boolean).join(" ")} />;
}
