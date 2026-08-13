import { describe, expect, it, vi } from "vitest";
import { createConsoleApi, RedPathApiError } from "../api";

const payloadByPath: Record<string, unknown> = {
  "/scope": { allowed_cidrs: ["192.0.2.0/24"], dry_run_default: true },
  "/kpis/executive": { risk_score: 61, detection_coverage_percent: 64, effective_coverage_percent: 58, open_critical_findings: 1, overdue_remediations: 0, expiring_acceptances: 0, evidence_review_backlog: 0 },
  "/scorecards/coverage": { expected_techniques: 5, detected_techniques: 3, open_gaps: 2, accepted_risks: 0, coverage_percent: 60, effective_coverage_percent: 55 },
  "/runs?limit=8": [],
  "/evidence": [],
  "/pcap/analyses?limit=6": [],
  "/evidence/e-1/pcap": { evidence: { evidence_id: "e-1" }, analysis: { analysis_id: "a-1" } },
  "/remediations/sla": [],
  "/detection-tuning": [],
  "/integrity/audit": { valid: true, event_count: 3, tail_digest: "abc" },
};

describe("typed console API client", () => {
  it("loads the complete analyst snapshot through same-origin GET endpoints", async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      expect(init?.method).toBe("GET");
      expect(init?.credentials).toBe("same-origin");
      return new Response(JSON.stringify(payloadByPath[`${url.pathname.replace("/api/v1", "")}${url.search}`]), { status: 200, headers: { "Content-Type": "application/json" } });
    });

    const snapshot = await createConsoleApi({ baseUrl: "https://redpath.example/api/v1/", fetchImpl }).getSnapshot();

    expect(fetchImpl).toHaveBeenCalledTimes(9);
    expect(snapshot.scope.dry_run_default).toBe(true);
    expect(snapshot.executiveKpis.risk_score).toBe(61);
    expect(snapshot.integrity.valid).toBe(true);
    expect(snapshot.pcapAnalyses).toEqual([]);
  });

  it("loads a linked PCAP evidence detail through a same-origin GET", async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(String(input)).toBe("https://redpath.example/api/v1/evidence/e-1/pcap");
      expect(init?.method).toBe("GET");
      expect(init?.credentials).toBe("same-origin");
      return new Response(JSON.stringify(payloadByPath["/evidence/e-1/pcap"]), { status: 200 });
    });

    const detail = await createConsoleApi({ baseUrl: "https://redpath.example/api/v1", fetchImpl }).getPcapEvidenceView!("e-1");

    expect(detail.evidence.evidence_id).toBe("e-1");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("returns a bounded error without exposing response content when a read fails", async () => {
    const api = createConsoleApi({
      baseUrl: "https://redpath.example/api/v1",
      fetchImpl: async () => new Response("server details should not reach the UI", { status: 503 }),
    });

    await expect(api.getSnapshot()).rejects.toEqual(new RedPathApiError(503, "Console data could not be loaded (HTTP 503)."));
  });
});
