export type RedMode = "manual" | "autonomous";

const storageKey = "mars-red-mode";

export function loadRememberedRedMode(): RedMode {
  try {
    return window.localStorage.getItem(storageKey) === "autonomous" ? "autonomous" : "manual";
  } catch {
    return "manual";
  }
}

export function rememberRedMode(mode: RedMode): void {
  try {
    window.localStorage.setItem(storageKey, mode);
  } catch {
    // Storage is an optional convenience; authorization never depends on it.
  }
}
