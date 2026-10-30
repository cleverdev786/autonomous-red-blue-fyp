import type { MouseEvent, ReactNode } from "react";
import { NavIcon } from "../../brand";
import type { Route } from "../../routes";
import { Button } from "./button";

/** Vite-native adaptation of the supplied sidebar, keeping MARS routing intact. */
export function Sidebar({ open, children }: { open: boolean; children: ReactNode }) {
  return (
    <aside className={`sidebar${open ? " menu-open" : ""}`} id="mars-navigation"
      role={open ? "dialog" : undefined} aria-modal={open ? true : undefined}
      aria-label={open ? "Navigation menu" : undefined}>
      {children}
    </aside>
  );
}

export function SidebarLink({ item, active, onNavigate }: {
  item: Route;
  active: boolean;
  onNavigate: (event: MouseEvent<HTMLAnchorElement>, path: string) => void;
}) {
  if (!item.section) return null;
  return (
    <Button asChild variant="ghost"><a href={item.path} title={item.title} aria-label={item.title}
      className={active ? "nav active" : "nav"}
      aria-current={active ? "page" : undefined}
      onClick={(event) => onNavigate(event, item.path)}>
      <NavIcon name={item.section} /><span className="nav-label">{item.title}</span>
      {active && <span className="nav-indicator" aria-hidden="true" />}
    </a></Button>
  );
}
