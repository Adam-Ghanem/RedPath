import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createConsoleApi, clearAccessToken, type FetchLike, setAccessToken } from "./api";
import AnalystDrilldown from "./AnalystDrilldown";
import type { ConsoleApi } from "./contracts";

afterEach(() => {
  clearAccessToken();
  vi.restoreAllMocks();
});

const session = {
  user_id: "user-alpha",
  username: "alpha-analyst",
  tenant_id: "tenant-alpha",
  tenant_slug: "alpha",
  roles: ["analyst"],
  session_version: 1,
};

describe("analyst drill-down boundary", () => {
  it("uses bounded, authenticated detail endpoints and URL-encodes resource IDs", async () => {
    setAccessToken("session-token");
    const fetchMock = vi.fn<FetchLike>().mockImplementation(async (input) => {
      const url = new URL(String(input));
      if (url.pathname.endsWith("/inventory/assets")) return new Response("[]", { status: 200 });
      if (url.pathname.endsWith("/detections/rules")) return new Response("[]", { status: 200 });
      if (url.pathname.endsWith("/cases/case%2Fone/export")) return new Response(JSON.stringify({ campaign: { campaign_id: "case/one" } }), { status: 200 });
      return new Response("{}", { status: 200 });
    });
    const api = createConsoleApi({ baseUrl: "https://redpath.example/api/v1", fetchImpl: fetchMock });

    await api.getAssets!({ limit: 999 });
    await api.getAssets!({ limit: 0 });
    await api.getDetectionRules!();
    await api.getCaseExport!("case/one");

    const assetCalls = fetchMock.mock.calls.filter(([input]) => String(input).includes("/inventory/assets"));
    expect(String(assetCalls[0][0])).toContain("/inventory/assets?limit=100");
    expect(String(assetCalls[1][0])).toContain("/inventory/assets?limit=1");
    expect(String(fetchMock.mock.calls[3][0])).toContain("/cases/case%2Fone/export");
    for (const [, init] of fetchMock.mock.calls) {
      expect((init?.headers as Headers).get("Authorization")).toBe("Bearer session-token");
      expect(init?.method).toBe("GET");
    }
  });

  it("renders accessible detail tabs and a resilient pending state before catalogs resolve", () => {
    const pendingApi: ConsoleApi = {
      getSnapshot: vi.fn(),
      getAssets: () => new Promise(() => undefined),
      getDetectionRules: () => new Promise(() => undefined),
    };
    const markup = renderToStaticMarkup(<AnalystDrilldown api={pendingApi} session={session} initialEvidence={[]} initialPcapAnalyses={[]} />);

    expect(markup).toContain('role="tablist"');
    expect(markup).toContain('role="tab"');
    expect(markup).toContain('aria-selected="true"');
    expect(markup).toContain('aria-controls="detail-panel"');
    expect(markup).toContain('role="tabpanel"');
    expect(markup).toContain("Loading authorised assets");
    expect(markup).not.toContain("AI-");
  });
});
