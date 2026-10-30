import React from "react";
import ReactDOM from "react-dom/client";
import { AuthenticatedApp } from "./LoginScreen";
import { TooltipProvider } from "./components/ui/tooltip";
import { NotificationCenter } from "./ui";
import "./tokens.css";
import "./styles.css";
import "./product.css";
import "./shell.css";
import "./workspace.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <TooltipProvider>
      <NotificationCenter />
      <AuthenticatedApp />
    </TooltipProvider>
  </React.StrictMode>,
);
