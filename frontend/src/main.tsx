import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import "./light-theme.css";
import "./forensic-casefile.css";
import "./forensic-reference-layout.css";
import "./forensic-reference-fidelity.css";
import "./forensic-exact-reference.css";
import "./forensic-polish.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
