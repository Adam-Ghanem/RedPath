import type {
  AnalystConsoleSnapshot,
  AssessmentRunSummary,
  ConsoleApi,
  CoverageScorecard,
  DetectionTuningItem,
  EvidenceResponse,
  ExecutiveKpis,
  IntegrityVerification,
  PcapAnalysisSummary,
  PcapEvidenceView,
  RemediationSlaItem,
  ScopeResponse,
} from "./contracts";

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

type ApiClientOptions = {
  baseUrl?: string;
  fetchImpl?: FetchLike;
};

export class RedPathApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = "RedPathApiError";
  }
}

const defaultBaseUrl = import.meta.env.VITE_REDPATH_API_BASE_URL ?? "/api/v1";

function normalizeBaseUrl(baseUrl: string) {
  return baseUrl.replace(/\/$/, "");
}

async function getJson<T>(fetchImpl: FetchLike, baseUrl: string, path: string): Promise<T> {
  const response = await fetchImpl(`${baseUrl}${path}`, {
    method: "GET",
    headers: { Accept: "application/json" },
    credentials: "same-origin",
  });

  if (!response.ok) {
    throw new RedPathApiError(response.status, `Console data could not be loaded (HTTP ${response.status}).`);
  }

  return response.json() as Promise<T>;
}

/**
 * The console intentionally exposes only GET operations. Mutating actions remain
 * behind server-side, role-authorized workflows rather than browser-side shortcuts.
 */
export function createConsoleApi(options: ApiClientOptions = {}): ConsoleApi {
  const baseUrl = normalizeBaseUrl(options.baseUrl ?? defaultBaseUrl);
  const fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);

  return {
    async getSnapshot(): Promise<AnalystConsoleSnapshot> {
      const [scope, executiveKpis, coverage, runs, evidence, pcapAnalyses, remediationSla, detectionTuning, integrity] = await Promise.all([
        getJson<ScopeResponse>(fetchImpl, baseUrl, "/scope"),
        getJson<ExecutiveKpis>(fetchImpl, baseUrl, "/kpis/executive"),
        getJson<CoverageScorecard>(fetchImpl, baseUrl, "/scorecards/coverage"),
        getJson<AssessmentRunSummary[]>(fetchImpl, baseUrl, "/runs?limit=8"),
        getJson<EvidenceResponse[]>(fetchImpl, baseUrl, "/evidence"),
        getJson<PcapAnalysisSummary[]>(fetchImpl, baseUrl, "/pcap/analyses?limit=6"),
        getJson<RemediationSlaItem[]>(fetchImpl, baseUrl, "/remediations/sla"),
        getJson<DetectionTuningItem[]>(fetchImpl, baseUrl, "/detection-tuning"),
        getJson<IntegrityVerification>(fetchImpl, baseUrl, "/integrity/audit"),
      ]);

      return { scope, executiveKpis, coverage, runs, evidence, pcapAnalyses, remediationSla, detectionTuning, integrity };
    },
    async getPcapEvidenceView(evidenceId: string): Promise<PcapEvidenceView> {
      return getJson<PcapEvidenceView>(fetchImpl, baseUrl, `/evidence/${encodeURIComponent(evidenceId)}/pcap`);
    },
  };
}

export const consoleApi = createConsoleApi();
