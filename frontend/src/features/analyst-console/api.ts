import type {
  AnalystConsoleSnapshot,
  AssessmentRunSummary,
  AuthLoginRequest,
  AuthMeResponse,
  AuthTokenResponse,
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

export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export type ApiClientOptions = {
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
let accessToken: string | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}

export function clearAccessToken() {
  accessToken = null;
}

export function hasAccessToken() {
  return accessToken !== null;
}

function normalizeBaseUrl(baseUrl: string) {
  return baseUrl.replace(/\/$/, "");
}

function errorMessage(status: number, operation: string) {
  if (status === 401) return "Authentication is required to view this workspace.";
  if (status === 403) return "Your authenticated role is not authorized for this workspace.";
  if (status === 429) return "The authenticated API rate limit was reached. Retry after a short delay.";
  return operation === "Console data" ? `Console data could not be loaded (HTTP ${status}).` : `${operation} could not be completed (HTTP ${status}).`;
}

async function getJson<T>(fetchImpl: FetchLike, baseUrl: string, path: string, signal?: AbortSignal): Promise<T> {
  const headers = new Headers({ Accept: "application/json" });
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);

  let response: Response;
  try {
    response = await fetchImpl(`${baseUrl}${path}`, {
      method: "GET",
      headers,
      credentials: "same-origin",
      signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new RedPathApiError(0, "The authenticated RedPath API is unavailable.");
  }

  if (!response.ok) throw new RedPathApiError(response.status, errorMessage(response.status, "Console data"));

  try {
    return (await response.json()) as T;
  } catch {
    throw new RedPathApiError(502, "The authenticated RedPath API returned an invalid response.");
  }
}

async function postJson<TRequest, TResponse>(fetchImpl: FetchLike, baseUrl: string, path: string, payload: TRequest): Promise<TResponse> {
  let response: Response;
  try {
    response = await fetchImpl(`${baseUrl}${path}`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(payload),
    });
  } catch {
    throw new RedPathApiError(0, "The authenticated RedPath API is unavailable.");
  }

  if (!response.ok) throw new RedPathApiError(response.status, errorMessage(response.status, "Authentication"));

  try {
    return (await response.json()) as TResponse;
  } catch {
    throw new RedPathApiError(502, "The authentication response was invalid.");
  }
}

/**
 * The workspace surface exposes GET operations only. Login is the sole POST
 * exception and only establishes an in-memory bearer session for read-only
 * requests; it does not create or mutate analyst resources.
 */
export function createConsoleApi(options: ApiClientOptions = {}): ConsoleApi {
  const baseUrl = normalizeBaseUrl(options.baseUrl ?? defaultBaseUrl);
  const fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);

  return {
    async login(request: AuthLoginRequest): Promise<AuthTokenResponse> {
      const token = await postJson<AuthLoginRequest, AuthTokenResponse>(fetchImpl, baseUrl, "/auth/token", request);
      setAccessToken(token.access_token);
      return token;
    },

    async getSession(): Promise<AuthMeResponse> {
      return getJson<AuthMeResponse>(fetchImpl, baseUrl, "/auth/me");
    },

    async getSnapshot(options?: { signal?: AbortSignal }): Promise<AnalystConsoleSnapshot> {
      const signal = options?.signal;
      const [scope, executiveKpis, coverage, runs, evidence, pcapAnalyses, remediationSla, detectionTuning, integrity] = await Promise.all([
        getJson<ScopeResponse>(fetchImpl, baseUrl, "/scope", signal),
        getJson<ExecutiveKpis>(fetchImpl, baseUrl, "/kpis/executive", signal),
        getJson<CoverageScorecard>(fetchImpl, baseUrl, "/scorecards/coverage", signal),
        getJson<AssessmentRunSummary[]>(fetchImpl, baseUrl, "/runs?limit=8", signal),
        getJson<EvidenceResponse[]>(fetchImpl, baseUrl, "/evidence", signal),
        getJson<PcapAnalysisSummary[]>(fetchImpl, baseUrl, "/pcap/analyses?limit=6", signal),
        getJson<RemediationSlaItem[]>(fetchImpl, baseUrl, "/remediations/sla", signal),
        getJson<DetectionTuningItem[]>(fetchImpl, baseUrl, "/detection-tuning", signal),
        getJson<IntegrityVerification>(fetchImpl, baseUrl, "/integrity/audit", signal),
      ]);

      return { scope, executiveKpis, coverage, runs, evidence, pcapAnalyses, remediationSla, detectionTuning, integrity };
    },

    async getPcapEvidenceView(evidenceId: string): Promise<PcapEvidenceView> {
      return getJson<PcapEvidenceView>(fetchImpl, baseUrl, `/evidence/${encodeURIComponent(evidenceId)}/pcap`);
    },

    logout() {
      clearAccessToken();
    },
  };
}

export const consoleApi = createConsoleApi();
