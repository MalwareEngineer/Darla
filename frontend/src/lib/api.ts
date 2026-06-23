import { getAuthHeaders } from "@/lib/auth-token";
import type {
  PaginatedResponse,
  KitSummary,
  KitDetail,
  KitDeletePreview,
  KitContentResponse,
  KitSubmitResponse,
  KitBulkResponse,
  KitBulkUploadResponse,
  SimilarKit,
  ScreenshotsResponse,
  NetworkLogResponse,
  BrowserResourcesResponse,
  DeobfuscationPreviewResponse,
  InvestigationSummary,
  InvestigationDetail,
  InvestigationTreeNode,
  InvestigationSubmitResponse,
  IndicatorSummary,
  IndicatorDetail,
  IndicatorStats,
  ActorSummary,
  ActorDetail,
  ActorStats,
  CampaignBrief,
  CampaignSummary,
  CampaignDetail,
  CampaignStats,
  CampaignYaraRuleCount,
  FamilySummary,
  FamilyDetail,
  FamilyStats,
  FamilyYaraRuleCount,
  HealthResponse,
  AnalysisResultDetail,
  TaskStatusResponse,
  DiffPairGroupsResponse,
  DiffablePair,
  DiffCompareResponse,
  MonitoredDomain,
  VictimSummary,
  VictimDetail,
  VictimObservation,
  VictimType,
  YaraStatusResponse,
  YaraCompileResult,
  YaraPlaygroundRequest,
  YaraPlaygroundResponse,
  YaraRuleFileSummary,
  YaraRuleFileSource,
  YaraSaveRuleResponse,
  YaraScannableFilesResponse,
} from "@/types/api";

const BASE = "/api/v1";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  // getAuthHeaders() returns {} in disabled mode and {Authorization: Bearer ...}
  // in OIDC mode.  Caller-supplied `init.headers` win on conflict so a future
  // call site can override the auth header explicitly if it ever needs to.
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
      ...init?.headers,
    },
    ...init,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `${res.status} ${res.statusText}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

// ── Kits ──

export const kits = {
  list: (params?: { offset?: number; limit?: number; status_filter?: string; source_feed?: string }) => {
    const q = new URLSearchParams();
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.status_filter) q.set("status_filter", params.status_filter);
    if (params?.source_feed) q.set("source_feed", params.source_feed);
    return request<PaginatedResponse<KitSummary>>(`/kits?${q}`);
  },
  get: (id: string) => request<KitDetail>(`/kits/${id}`),
  submit: (url: string, source_feed?: string, force?: boolean, entityIds?: { actor_id?: string; campaign_id?: string; family_id?: string }) =>
    request<KitSubmitResponse>("/kits", {
      method: "POST",
      body: JSON.stringify({ url, source_feed, force, ...entityIds }),
    }),
  upload: async (file: File, source_feed?: string, entityIds?: { actor_id?: string; campaign_id?: string; family_id?: string }) => {
    const form = new FormData();
    form.append("file", file);
    if (source_feed) form.append("source_feed", source_feed);
    if (entityIds?.actor_id) form.append("actor_id", entityIds.actor_id);
    if (entityIds?.campaign_id) form.append("campaign_id", entityIds.campaign_id);
    if (entityIds?.family_id) form.append("family_id", entityIds.family_id);
    // FormData uploads — let the browser set Content-Type with the
    // multipart boundary, but still attach the bearer token via
    // getAuthHeaders() (no-op in disabled mode).
    const res = await fetch(`${BASE}/kits/upload`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: form,
    });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
    return res.json() as Promise<KitSubmitResponse>;
  },
  actors: (id: string) =>
    request<{ id: string; name: string }[]>(`/kits/${id}/actors`),
  similar: (id: string, threshold?: number) => {
    const q = threshold ? `?threshold=${threshold}` : "";
    return request<SimilarKit[]>(`/kits/${id}/similar${q}`);
  },
  indicators: (id: string, offset = 0, limit = 50) =>
    request<PaginatedResponse<IndicatorSummary>>(`/kits/${id}/indicators?offset=${offset}&limit=${limit}`),
  reanalyze: (id: string) =>
    request<{ kit_id: string; task_id: string }>(`/kits/${id}/reanalyze`, { method: "POST" }),
  bulkSubmit: (urls: string[], entityIds?: { actor_id?: string; campaign_id?: string; family_id?: string }) =>
    request<KitBulkResponse>("/kits/bulk", {
      method: "POST",
      body: JSON.stringify({ urls, ...entityIds }),
    }),
  bulkUpload: async (files: File[], entityIds?: { actor_id?: string; campaign_id?: string; family_id?: string }) => {
    const form = new FormData();
    for (const file of files) form.append("files", file);
    if (entityIds?.actor_id) form.append("actor_id", entityIds.actor_id);
    if (entityIds?.campaign_id) form.append("campaign_id", entityIds.campaign_id);
    if (entityIds?.family_id) form.append("family_id", entityIds.family_id);
    const res = await fetch(`${BASE}/kits/upload/bulk`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: form,
    });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
    return res.json() as Promise<KitBulkUploadResponse>;
  },
  delete: (id: string) => request<void>(`/kits/${id}`, { method: "DELETE" }),
  deletePreview: (id: string) => request<KitDeletePreview>(`/kits/${id}/delete-preview`),
  content: (id: string) => request<KitContentResponse>(`/kits/${id}/content`),
  screenshots: (id: string) => request<ScreenshotsResponse>(`/kits/${id}/screenshots`),
  networkLog: (id: string) => request<NetworkLogResponse>(`/kits/${id}/network-log`),
  browserResources: (id: string) => request<BrowserResourcesResponse>(`/kits/${id}/browser-resources`),
  deobfuscationPreview: (id: string) => request<DeobfuscationPreviewResponse>(`/kits/${id}/deobfuscation-preview`),
  addToCampaign: (kitId: string, campaignId: string) =>
    request<{ added: number; kit_id: string; used_root: boolean; message: string }>(
      `/kits/${kitId}/add-to-campaign`,
      { method: "POST", body: JSON.stringify({ campaign_id: campaignId }) },
    ),
  addToActor: (kitId: string, actorId: string) =>
    request<{ linked: number; kit_id: string; used_root: boolean; message: string }>(
      `/kits/${kitId}/add-to-actor`,
      { method: "POST", body: JSON.stringify({ actor_id: actorId }) },
    ),
  addToFamily: (kitId: string, familyId: string) =>
    request<{ added: number; kit_id: string; used_root: boolean; message: string }>(
      `/kits/${kitId}/add-to-family`,
      { method: "POST", body: JSON.stringify({ family_id: familyId }) },
    ),
  bulkDelete: (ids: string[]) =>
    request<{ deleted: number }>("/kits/bulk-delete", {
      method: "POST",
      body: JSON.stringify({ ids }),
    }),
  search: (params: { q?: string; yara_rule?: string; tlsh?: string; tlsh_threshold?: number; offset?: number; limit?: number }) => {
    const q = new URLSearchParams();
    if (params.q) q.set("q", params.q);
    if (params.yara_rule) q.set("yara_rule", params.yara_rule);
    if (params.tlsh) q.set("tlsh", params.tlsh);
    if (params.tlsh_threshold) q.set("tlsh_threshold", String(params.tlsh_threshold));
    if (params.offset) q.set("offset", String(params.offset));
    if (params.limit) q.set("limit", String(params.limit));
    return request<PaginatedResponse<KitSummary>>(`/kits/search?${q}`);
  },
};

// ── Investigations ──

export const investigations = {
  list: (offset = 0, limit = 50) =>
    request<PaginatedResponse<InvestigationSummary>>(`/investigations?offset=${offset}&limit=${limit}`),
  get: (id: string) => request<InvestigationDetail>(`/investigations/${id}`),
  tree: (id: string) => request<InvestigationTreeNode[]>(`/investigations/${id}/tree`),
  kits: (id: string, offset = 0, limit = 50) =>
    request<PaginatedResponse<KitSummary>>(`/investigations/${id}/kits?offset=${offset}&limit=${limit}`),
  create: (data: {
    name: string;
    url: string;
    max_depth?: number;
    actor_id?: string;
    campaign_id?: string;
    family_id?: string;
  }) =>
    request<InvestigationSubmitResponse>("/investigations", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  createFromFile: async (formData: FormData) => {
    const res = await fetch(`${BASE}/investigations/upload`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: formData,
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || `${res.status} ${res.statusText}`);
    }
    return res.json() as Promise<InvestigationSubmitResponse>;
  },
  update: (id: string, data: Partial<InvestigationDetail>) =>
    request<InvestigationDetail>(`/investigations/${id}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),
  delete: (id: string) => request<void>(`/investigations/${id}`, { method: "DELETE" }),
  bulkDelete: (ids: string[]) =>
    request<{ deleted: number }>("/investigations/bulk-delete", {
      method: "POST",
      body: JSON.stringify({ ids }),
    }),
};

// ── Indicators ──

export const indicators = {
  list: (params?: { offset?: number; limit?: number; type_filter?: string }) => {
    const q = new URLSearchParams();
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.type_filter) q.set("type_filter", params.type_filter);
    return request<PaginatedResponse<IndicatorSummary>>(`/indicators?${q}`);
  },
  search: (query: string, params?: { offset?: number; limit?: number; type_filter?: string }) => {
    const q = new URLSearchParams({ q: query });
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.type_filter) q.set("type_filter", params.type_filter);
    return request<PaginatedResponse<IndicatorSummary>>(`/indicators/search?${q}`);
  },
  stats: () => request<IndicatorStats[]>("/indicators/stats"),
  get: (id: string) => request<IndicatorDetail>(`/indicators/${id}`),
};

// ── Actors ──

export const actors = {
  list: (offset = 0, limit = 50) =>
    request<PaginatedResponse<ActorSummary>>(`/actors?offset=${offset}&limit=${limit}`),
  get: (id: string) => request<ActorDetail>(`/actors/${id}`),
  create: (data: { name: string; aliases?: string[]; description?: string; email_addresses?: string[]; telegram_handles?: string[] }) =>
    request<ActorDetail>("/actors", { method: "POST", body: JSON.stringify(data) }),
  update: (id: string, data: Partial<ActorDetail>) =>
    request<ActorDetail>(`/actors/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  delete: (id: string) =>
    request<void>(`/actors/${id}`, { method: "DELETE" }),
  link: (id: string, indicator_ids: string[]) =>
    request<{ linked: number }>(`/actors/${id}/link`, {
      method: "POST",
      body: JSON.stringify({ indicator_ids }),
    }),
  // Drill-down endpoints powering the rebuilt detail-page tabs.
  stats: (id: string) => request<ActorStats>(`/actors/${id}/stats`),
  kits: (id: string, params?: { offset?: number; limit?: number; status?: string }) => {
    const q = new URLSearchParams();
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.status) q.set("status", params.status);
    return request<PaginatedResponse<KitSummary>>(`/actors/${id}/kits?${q}`);
  },
  indicators: (id: string, offset = 0, limit = 50) =>
    request<PaginatedResponse<IndicatorSummary>>(
      `/actors/${id}/indicators?offset=${offset}&limit=${limit}`,
    ),
  campaigns: (id: string) =>
    request<CampaignBrief[]>(`/actors/${id}/campaigns`),
  families: (id: string) =>
    request<FamilySummary[]>(`/actors/${id}/families`),
};

// ── Campaigns ──

export const campaigns = {
  list: (params?: { offset?: number; limit?: number; target_brand?: string }) => {
    const q = new URLSearchParams();
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.target_brand) q.set("target_brand", params.target_brand);
    return request<PaginatedResponse<CampaignSummary>>(`/campaigns?${q}`);
  },
  get: (id: string) => request<CampaignDetail>(`/campaigns/${id}`),
  create: (data: { name: string; description?: string; target_brand?: string }) =>
    request<CampaignDetail>("/campaigns", { method: "POST", body: JSON.stringify(data) }),
  update: (id: string, data: Partial<CampaignDetail>) =>
    request<CampaignDetail>(`/campaigns/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  delete: (id: string) =>
    request<void>(`/campaigns/${id}`, { method: "DELETE" }),
  addKits: (id: string, kit_ids: string[]) =>
    request<{ added: number }>(`/campaigns/${id}/kits`, {
      method: "POST",
      body: JSON.stringify({ kit_ids }),
    }),
  // Drill-down endpoints powering the rebuilt campaign-detail tabs.
  stats: (id: string) => request<CampaignStats>(`/campaigns/${id}/stats`),
  // GET sibling of POST /campaigns/{id}/kits — backend uses
  // /kits-list to disambiguate verb collision (same pattern as
  // /families/{id}/actors-list).
  kits: (id: string, params?: { offset?: number; limit?: number; status?: string }) => {
    const q = new URLSearchParams();
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.status) q.set("status", params.status);
    return request<PaginatedResponse<KitSummary>>(`/campaigns/${id}/kits-list?${q}`);
  },
  indicators: (id: string, offset = 0, limit = 50) =>
    request<PaginatedResponse<IndicatorSummary>>(
      `/campaigns/${id}/indicators?offset=${offset}&limit=${limit}`,
    ),
  victims: (id: string, offset = 0, limit = 50) =>
    request<PaginatedResponse<VictimSummary>>(
      `/campaigns/${id}/victims?offset=${offset}&limit=${limit}`,
    ),
  actors: (id: string) =>
    request<ActorSummary[]>(`/campaigns/${id}/actors`),
  families: (id: string) =>
    request<FamilySummary[]>(`/campaigns/${id}/families`),
  yaraRules: (id: string) =>
    request<CampaignYaraRuleCount[]>(`/campaigns/${id}/yara-rules`),
};

// ── Families ──

export const families = {
  list: (offset = 0, limit = 50) =>
    request<PaginatedResponse<FamilySummary>>(`/families?offset=${offset}&limit=${limit}`),
  get: (id: string) => request<FamilyDetail>(`/families/${id}`),
  create: (data: { name: string; aliases?: string[]; description?: string }) =>
    request<FamilyDetail>("/families", { method: "POST", body: JSON.stringify(data) }),
  update: (id: string, data: Partial<FamilyDetail>) =>
    request<FamilyDetail>(`/families/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  delete: (id: string) =>
    request<void>(`/families/${id}`, { method: "DELETE" }),
  addKits: (id: string, kit_ids: string[]) =>
    request<{ added: number }>(`/families/${id}/kits`, {
      method: "POST",
      body: JSON.stringify({ kit_ids }),
    }),
  addActors: (id: string, actor_ids: string[]) =>
    request<{ added: number }>(`/families/${id}/actors`, {
      method: "POST",
      body: JSON.stringify({ actor_ids }),
    }),
  // Drill-down endpoints powering the rebuilt family-detail tabs.
  stats: (id: string) => request<FamilyStats>(`/families/${id}/stats`),
  kits: (id: string, params?: { offset?: number; limit?: number; status?: string }) => {
    const q = new URLSearchParams();
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.status) q.set("status", params.status);
    return request<PaginatedResponse<KitSummary>>(`/families/${id}/kits?${q}`);
  },
  indicators: (id: string, offset = 0, limit = 50) =>
    request<PaginatedResponse<IndicatorSummary>>(
      `/families/${id}/indicators?offset=${offset}&limit=${limit}`,
    ),
  yaraRules: (id: string) =>
    request<FamilyYaraRuleCount[]>(`/families/${id}/yara-rules`),
  // GET sibling of POST /families/{id}/actors — different verb on the
  // same path would collide in URLSearchParams routers, so backend
  // uses /actors-list for the GET.
  actors: (id: string) =>
    request<ActorSummary[]>(`/families/${id}/actors-list`),
  campaigns: (id: string) =>
    request<CampaignSummary[]>(`/families/${id}/campaigns`),
};

// ── Analysis ──

export const analysis = {
  result: (id: string) => request<AnalysisResultDetail>(`/analysis/results/${id}`),
  taskStatus: (taskId: string) => request<TaskStatusResponse>(`/analysis/tasks/${taskId}`),
};

// ── PhishDiff ──

export const diff = {
  pairGroups: (params?: { offset?: number; limit?: number; max_distance?: number; max_size_ratio?: number }) => {
    const q = new URLSearchParams();
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.max_distance) q.set("max_distance", String(params.max_distance));
    if (params?.max_size_ratio) q.set("max_size_ratio", String(params.max_size_ratio));
    return request<DiffPairGroupsResponse>(`/diff/pairs?${q}`);
  },
  pairs: (kitId: string, params?: { max_distance?: number; max_size_ratio?: number }) => {
    const q = new URLSearchParams();
    if (params?.max_distance) q.set("max_distance", String(params.max_distance));
    if (params?.max_size_ratio) q.set("max_size_ratio", String(params.max_size_ratio));
    return request<DiffablePair[]>(`/diff/pairs/${kitId}?${q}`);
  },
  compare: (kit_a_id: string, kit_b_id: string, normalize = false) =>
    request<DiffCompareResponse>("/diff/compare", {
      method: "POST",
      body: JSON.stringify({ kit_a_id, kit_b_id, normalize }),
    }),
};

// ── PhishMatch ──

export type PhishMatchEntityType = "actor" | "family" | "campaign";

export interface PhishMatchSignals {
  total: number;
  tlsh: number;
  ioc: number;
  yara: number;
  source_url: number;
  redirect_chain: number;
  evidence: {
    tlsh: Array<{ kit_id: string; distance: number; tlsh: string }>;
    ioc: Array<{
      type: string;
      value: string;
      weight: number;
      subject_indicator_id: string;
      peer_indicator_id: string;
      peer_kit_id: string;
    }>;
    yara: string[];
    source_url: string[];
    redirect: string[];
  };
}

export interface PhishMatchCandidate {
  entity_type: PhishMatchEntityType;
  entity_id: string;
  entity_name: string;
  auto_generated: boolean;
  score: number;
  signals: PhishMatchSignals;
  supporting_kit_ids: string[];
}

export interface PhishMatchResult {
  kit_id: string;
  actors: PhishMatchCandidate[];
  families: PhishMatchCandidate[];
  campaigns: PhishMatchCandidate[];
  no_matches_reason: string | null;
  min_surface_score: number;
}

export interface PhishMatchSuggestion {
  kit_id: string;
  source_url: string;
  sha256: string | null;
  score: number;
  via_kit_id: string | null;
  signals: PhishMatchSignals;
}

export interface PhishMatchSuggestionsResponse {
  entity_type: PhishMatchEntityType;
  entity_id: string;
  suggestions: PhishMatchSuggestion[];
}

export const phishmatch = {
  /** Rank candidate entities for a kit. */
  scoreKit: (kitId: string) =>
    request<PhishMatchResult>(`/phishmatch/kit/${kitId}`),

  /** Reverse lookup — unattributed kits that score high against an entity. */
  suggestKits: (
    entityType: PhishMatchEntityType,
    entityId: string,
    limit = 20,
  ) =>
    request<PhishMatchSuggestionsResponse>(
      `/phishmatch/entity/${entityType}/${entityId}?limit=${limit}`,
    ),

  /** Commit an attribution (kit → entity link) with evidence. */
  attribute: (kitId: string, payload: {
    entity_type: PhishMatchEntityType;
    entity_id: string;
    confidence: "verified" | "suspected";
    attributed_by?: string | null;
    evidence_snapshot?: PhishMatchSignals | null;
  }) =>
    request<{
      kit_id: string;
      entity_type: PhishMatchEntityType;
      entity_id: string;
      created: boolean;
      confidence: string;
      attributed_at: string;
    }>(`/phishmatch/kit/${kitId}/attribute`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  /** Remove a kit → entity link. */
  unattribute: (
    kitId: string,
    entityType: PhishMatchEntityType,
    entityId: string,
  ) =>
    request<void>(
      `/phishmatch/kit/${kitId}/attribute?entity_type=${entityType}&entity_id=${entityId}`,
      { method: "DELETE" },
    ),
};

// ── PhishPrint ──
//
// Writes for monitored-domains and victims live behind `darla-admin`
// (RFC §9, Phase 6b).  Only read methods are exposed here.

export const monitoredDomains = {
  list: (offset = 0, limit = 200) =>
    request<PaginatedResponse<MonitoredDomain>>(
      `/monitored-domains?offset=${offset}&limit=${limit}`,
    ),
  get: (id: string) =>
    request<MonitoredDomain>(`/monitored-domains/${id}`),
};

export const victims = {
  list: (params?: {
    offset?: number;
    limit?: number;
    domain?: string;
    type?: VictimType;
    search?: string;
  }) => {
    const q = new URLSearchParams();
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.domain) q.set("domain", params.domain);
    if (params?.type) q.set("type", params.type);
    if (params?.search) q.set("search", params.search);
    return request<PaginatedResponse<VictimSummary>>(`/victims?${q}`);
  },
  get: (id: string) => request<VictimDetail>(`/victims/${id}`),
  observations: (id: string, offset = 0, limit = 100) =>
    request<PaginatedResponse<VictimObservation>>(
      `/victims/${id}/observations?offset=${offset}&limit=${limit}`,
    ),
};

// ── YARA Playground ──

export const yara = {
  status: () => request<YaraStatusResponse>("/yara/status"),
  compile: (rule_source: string) =>
    request<YaraCompileResult>("/yara/compile", {
      method: "POST",
      body: JSON.stringify({ rule_source }),
    }),
  playground: (req: YaraPlaygroundRequest) =>
    request<YaraPlaygroundResponse>("/yara/playground", {
      method: "POST",
      body: JSON.stringify(req),
    }),
  rules: () => request<YaraRuleFileSummary[]>("/yara/rules"),
  rule: (name: string) =>
    request<YaraRuleFileSource>(`/yara/rules/${encodeURIComponent(name)}`),
  saveUserRule: (name: string, content: string) =>
    request<YaraSaveRuleResponse>(`/yara/rules/user/${encodeURIComponent(name)}`, {
      method: "PUT",
      body: JSON.stringify({ content }),
    }),
  deleteUserRule: (name: string) =>
    request<void>(`/yara/rules/user/${encodeURIComponent(name)}`, { method: "DELETE" }),
  scannableFiles: (kitId: string, max_size_mb?: number) => {
    const q = max_size_mb ? `?max_size_mb=${max_size_mb}` : "";
    return request<YaraScannableFilesResponse>(`/yara/scannable-files/${kitId}${q}`);
  },
};

// ── Health ──

export const health = {
  // ``/health`` is the anonymous LB liveness probe — returns 200/503
  // with no body so it must NOT be JSON-parsed.  ``/health/detail`` is
  // the analyst-gated triage endpoint that returns DB/Redis status.
  // The header badge calls /detail because the SPA is always running
  // inside the Shell guard, so the user is already authenticated.
  check: () => request<HealthResponse>("/health/detail"),
};
