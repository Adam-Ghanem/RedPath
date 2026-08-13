import { afterEach, describe, expect, it, vi } from "vitest";
import { clearAccessToken, createConsoleApi, type FetchLike, RedPathApiError, setAccessToken } from "./api";

const jsonResponse = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });

const session = {
  user_id: "user-alpha",
  username: "alpha-analyst",
  tenant_id: "tenant-alpha",
  tenant_slug: "alpha",
  roles: ["analyst"],
  session_version: 3,
};

const token = {
  access_token: "opaque-session-token",
  token_type: "bearer" as const,
  expires_at: "2099-01-01T00:00:00Z",
  user_id: "user-alpha",
  username: "alpha-analyst",
  tenant_id: "tenant-alpha",
  tenant_slug: "alpha",
  roles: ["analyst"],
};

function snapshotResponse(path: string) {
  if (path === "/auth/me") return jsonResponse(session);
  if (path === "/scope") return jsonResponse({ allowed_cidrs: ["192.168.56.0/24"], dry_run_default: true });
  if (path === "/kpis/executive") return jsonResponse({ risk_score: 62, detection_coverage_percent: 75, effective_coverage_percent: 70, open_critical_findings: 1, overdue_remediations: 0, expiring_acceptances: 0, evidence_review_backlog: 0 });
  if (path === "/scorecards/coverage") return jsonResponse({ expected_techniques: 4, detected_techniques: 3, open_gaps: 1, accepted_risks: 0, coverage_percent: 75, effective_coverage_percent: 70 });
  if (path === "/runs") return jsonResponse([]);
  if (path === "/evidence") return jsonResponse([]);
  if (path === "/remediations/sla") return jsonResponse([]);
  if (path === "/detection-tuning") return jsonResponse([]);
  if (path === "/integrity/audit") return jsonResponse({ valid: true, event_count: 4, tail_digest: "digest" });
  throw new Error(`Unexpected endpoint ${path}`);
}

afterEach(() => {
  clearAccessToken();
  vi.restoreAllMocks();
});

describe("authenticated read-only analyst API", () => {
  it("uses the server-derived session and bearer token for every read-only request", async () => {
    setAccessToken(token.access_token);
    const fetchMock = vi.fn<FetchLike>().mockImplementation(async (input) => {
      const url = new URL(String(input), "https://redpath.test");
      return snapshotResponse(url.pathname.replace("/api/v1", ""));
    });
    const api = createConsoleApi({ baseUrl: "https://redpath.test/api/v1", fetchImpl: fetchMock });

    const actualSession = await api.getSession!();
    const snapshot = await api.getSnapshot();

    expect(actualSession.username).toBe("alpha-analyst");
    expect(actualSession.tenant_slug).toBe("alpha");
    expect(snapshot.scope.dry_run_default).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(9);
    for (const [, init] of fetchMock.mock.calls) {
      expect((init?.headers as Headers).get("Authorization")).toBe(`Bearer ${token.access_token}`);
      expect(init?.method).toBe("GET");
    }
  });

  it("uses the auth token endpoint only to establish an in-memory bearer session", async () => {
    const fetchMock = vi.fn<FetchLike>()
      .mockResolvedValueOnce(jsonResponse(token))
      .mockResolvedValueOnce(jsonResponse(session));
    const api = createConsoleApi({ baseUrl: "https://redpath.test/api/v1", fetchImpl: fetchMock });

    const loginResult = await api.login!({ tenant_slug: "alpha", username: "alpha-analyst", password: "not-checked-in" });
    await api.getSession!();

    expect(loginResult.access_token).toBe(token.access_token);
    expect(fetchMock.mock.calls[0][1]?.method).toBe("POST");
    expect(fetchMock.mock.calls[0][1]?.body).toBe(JSON.stringify({ tenant_slug: "alpha", username: "alpha-analyst", password: "not-checked-in" }));
    expect((fetchMock.mock.calls[1][1]?.headers as Headers).get("Authorization")).toBe(`Bearer ${token.access_token}`);
  });

  it("normalizes unauthorized and rate-limit responses without exposing backend payloads", async () => {
    const unauthorized = vi.fn<FetchLike>().mockResolvedValue(new Response("secret backend detail", { status: 401 }));
    const rateLimited = vi.fn<FetchLike>().mockResolvedValue(new Response("internal rate limit detail", { status: 429 }));

    await expect(createConsoleApi({ baseUrl: "https://redpath.test/api/v1", fetchImpl: unauthorized }).getSession!()).rejects.toMatchObject({ status: 401, message: "Authentication is required to view this workspace." });
    await expect(createConsoleApi({ baseUrl: "https://redpath.test/api/v1", fetchImpl: rateLimited }).getSession!()).rejects.toMatchObject({ status: 429, message: "The authenticated API rate limit was reached. Retry after a short delay." });
    await expect(createConsoleApi({ baseUrl: "https://redpath.test/api/v1", fetchImpl: unauthorized }).getSession!()).rejects.toBeInstanceOf(RedPathApiError);
  });
});
