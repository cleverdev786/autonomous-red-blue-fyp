import React from "react";
import ReactDOM from "react-dom/client";
import { AuthenticatedApp } from "./LoginScreen";
import "./tokens.css";
import "./styles.css";
import "./product.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <AuthenticatedApp />
  </React.StrictMode>,
);
