import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import Home from "../../App";
import type { ConsoleApi } from "./contracts";
import { AnalystConsole, SessionIdentity, SessionRequired, SnapshotError } from "./AnalystConsole";

const session = {
  user_id: "user-alpha",
  username: "alpha-analyst",
  tenant_id: "tenant-alpha",
  tenant_slug: "alpha",
  roles: ["analyst"],
  session_version: 3,
};

const pendingApi: ConsoleApi = {
  getSession: () => new Promise(() => undefined),
  getSnapshot: () => new Promise(() => undefined),
};

describe("authenticated analyst workspace", () => {
  it("renders the workspace entry in the main frontend navigation", () => {
    const markup = renderToStaticMarkup(<Home />);

    expect(markup).toContain("Analyst console");
    expect(markup).toContain("#analyst-console");
  });

  it("renders a resilient loading state before authenticated data resolves", () => {
    const markup = renderToStaticMarkup(<AnalystConsole api={pendingApi} />);

    expect(markup).toContain('role="status"');
    expect(markup).toContain("Loading the authenticated, read-only SOC summary.");
  });

  it("renders server-derived identity and no mock review actor", () => {
    const identityMarkup = renderToStaticMarkup(<SessionIdentity session={session} onLogout={() => undefined} />);
    const authMarkup = renderToStaticMarkup(<SessionRequired api={{ getSnapshot: vi.fn() }} message="Authentication is required." retry={() => undefined} onExit={() => undefined} />);

    expect(identityMarkup).toContain("alpha-analyst");
    expect(identityMarkup).toContain("alpha · analyst");
    expect(identityMarkup).not.toContain("mock");
    expect(identityMarkup).not.toContain("Reviewed by");
    expect(authMarkup).toContain("Actor identity, tenant scope, roles, and audit attribution are supplied by the server");
    expect(authMarkup).toContain('autoComplete="username"');
  });

  it("uses alert semantics and a keyboard-reachable retry control for API failures", () => {
    const markup = renderToStaticMarkup(<SnapshotError message="Authentication is required to view this workspace." status={401} retry={() => undefined} onExit={() => undefined} />);

    expect(markup).toContain('role="alert"');
    expect(markup).toContain("Retry read-only refresh");
    expect(markup).toContain("Return to RedPath home");
  });
});
