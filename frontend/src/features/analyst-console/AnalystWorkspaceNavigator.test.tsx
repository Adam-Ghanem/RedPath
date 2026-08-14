import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import AnalystWorkspaceNavigator from "./AnalystWorkspaceNavigator";
import type { ConsoleApi } from "./contracts";

const api: ConsoleApi = { getSnapshot: vi.fn() };
const session = { user_id: "user-1", username: "analyst", tenant_id: "tenant-1", tenant_slug: "tenant", roles: ["viewer"], session_version: 1 };

describe("high-throughput analyst workspace", () => {
  it("renders keyboard tabs, saved filters, breadcrumbs, and stale-data degradation state", () => {
    const markup = renderToStaticMarkup(<AnalystWorkspaceNavigator api={api} session={session} initialEvidence={[]} initialPcapAnalyses={[]} snapshotRefreshedAt={new Date(0)} />);

    expect(markup).toContain('role="tablist"');
    expect(markup).toContain('aria-label="High-throughput data views"');
    expect(markup).toContain('aria-label="Saved analyst filter"');
    expect(markup).toContain('aria-label="Workspace breadcrumb"');
    expect(markup).toContain("Telemetry stale");
    expect(markup).toContain("Viewer · read-only");
    expect(markup).toContain("Loading authorised catalog");
  });
});
