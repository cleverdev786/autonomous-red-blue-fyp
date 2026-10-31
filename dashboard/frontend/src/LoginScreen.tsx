import { useEffect, useState } from "react";
import App from "./App";
import { MarsMark } from "./brand";
import { ActionButton } from "./ui";
import { Eye, EyeOff, Moon, Sun } from "lucide-react";

type AuthState = "checking" | "signed-out" | "signed-in";

export function AuthenticatedApp() {
  const [state, setState] = useState<AuthState>("checking");
  useEffect(() => {
    void fetch("/api/auth/session", { credentials: "include" })
      .then(response => setState(response.ok ? "signed-in" : "signed-out"))
      .catch(() => setState("signed-out"));
  }, []);
  if (state === "signed-in") return <App />;
  return <LoginScreen checking={state === "checking"} onSignedIn={() => setState("signed-in")} />;
}

export function LoginScreen({ checking, onSignedIn }: { checking: boolean; onSignedIn: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [theme, setTheme] = useState(() => typeof document !== "undefined" && document.documentElement.dataset.theme === "dark" ? "dark" : "light");
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    try { window.localStorage.setItem("mars-theme", theme); } catch { /* Storage is optional. */ }
  }, [theme]);
  return <main className="login-page">
      <div className="login-utilities"><button type="button" className="login-icon" aria-label={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}
        onClick={() => setTheme(theme === "light" ? "dark" : "light")}>
        {theme === "light" ? <Moon size={20} /> : <Sun size={20} />}</button></div>
    <section className="login-card" aria-labelledby="login-title">
      <div className="login-brand"><MarsMark className="login-mark" />
        <span className="eyebrow">MARS security workspace</span></div>
      <h1 id="login-title">Welcome back</h1>
      <p>Sign in once to access the complete local application.</p>
      {error && <div className="login-error" role="alert">{error}</div>}
      <form onSubmit={event => {
        event.preventDefault();
        setBusy(true); setError("");
        void fetch("/api/auth/login", {
          method: "POST", credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
        }).then(response => {
          if (!response.ok) throw new Error();
          onSignedIn();
        }).catch(() => setError("Invalid username or password."))
          .finally(() => setBusy(false));
      }}>
        <label htmlFor="login-username">Username</label>
        <input id="login-username" autoComplete="username" required value={username}
          onChange={event => setUsername(event.target.value)} />
        <label htmlFor="login-password">Password</label>
        <div className="password-field"><input id="login-password" type={showPassword ? "text" : "password"} autoComplete="current-password" required
          value={password} onChange={event => setPassword(event.target.value)} />
          <button type="button" className="login-icon" aria-label={showPassword ? "Hide password" : "Show password"}
            aria-pressed={showPassword} onClick={() => setShowPassword(!showPassword)}>
            {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}</button></div>
        <ActionButton type="submit" disabled={checking || busy}>
          {checking ? "Checking session…" : busy ? "Signing in…" : "Sign in"}
        </ActionButton>
      </form>
    </section>
  </main>;
}
