// ── Enums ──

export type KitStatus =
  | "pending"
  | "downloading"
  | "downloaded"
  | "analyzing"
  | "analyzed"
  | "failed";

export type IndicatorType =
  | "email"
  | "telegram_bot_token"
  | "telegram_chat_id"
  | "telegram_handle"
  | "c2_url"
  | "ip_address"
  | "smtp_credential"
  | "base64_block"
  | "domain"
  | "phone_number"
  | "cryptocurrency_wallet"
  | "source_url";

export type AnalysisType =
  | "hash"
  | "ioc_extraction"
  | "deobfuscation"
  | "yara_scan"
  | "similarity"
  | "eml_parse"
  | "qr_decode"
  | "link_score"
  | "redirect_chain"
  | "external_js_fetch"
  | "polymorphism"
  | "artifact_render"
  | "svg_active_exec"
  | "oauth_authorize";

// ── Paginated response ──

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
}

// ── Kits ──

export interface KitSummary {
  id: string;
  source_url: string;
  sha256?: string;
  tlsh?: string;
  status: KitStatus;
  file_size?: number;
  source_feed?: string;
  created_at: string;
}

export interface KitDetail extends KitSummary {
  md5?: string;
  sha1?: string;
  filename?: string;
  mime_type?: string;
  error_message?: string;
  parent_kit_id?: string;
  investigation_id?: string;
  chain_depth: number;
  discovery_method?: string;
  indicators: IndicatorBrief[];
  analysis_results: AnalysisResultBrief[];
  campaigns: CampaignBrief[];
  families: FamilyBrief[];
  actors: ActorBrief[];
  child_kits: KitSummary[];
}

export interface KitSubmitResponse {
  kit_id: string;
  task_id: string;
  duplicate: boolean;
  message: string;
}

export interface KitBulkResponse {
  submitted: number;
  skipped_duplicate: number;
  results: { url: string; kit_id: string; task_id?: string; duplicate: boolean }[];
}

export interface KitBulkUploadResult {
  filename: string;
  kit_id: string;
  task_id?: string;
  investigation_id?: string;
}

export interface KitBulkUploadResponse {
  submitted: number;
  results: KitBulkUploadResult[];
}

export interface SimilarKit {
  id: string;
  sha256?: string;
  tlsh?: string;
  source_url: string;
  distance: number;
}

export interface KitDeletePreview {
  kit_id: string;
  total_kits: number;
  child_kits: number;
  indicators: number;
  analysis_results: number;
  campaign_links: number;
  investigations: number;
}

// ── Investigations ──

export interface InvestigationSummary {
  id: string;
  name?: string;
  description?: string;
  status: string;
  max_depth: number;
  total_kits: number;
  total_depth_reached: number;
  created_at: string;
}

export interface InvestigationDetail extends InvestigationSummary {
  root_kit?: KitSummary;
}

export interface InvestigationTreeNode {
  kit: KitSummary;
  discovery_method?: string;
  chain_depth: number;
  children: InvestigationTreeNode[];
  // For browser_render kits: ordered hosts the render navigated through
  // (lure → gate → credential page), which the single node collapses.
  nav_path?: string[] | null;
}

export interface InvestigationSubmitResponse {
  investigation_id: string;
  kit_id: string;
  task_id: string;
  message: string;
}

// ── Indicators ──

export interface IndicatorSummary {
  id: string;
  type: IndicatorType;
  value: string;
  confidence: number;
  source_file?: string;
  context?: string;
  kit_id: string;
  created_at: string;
}

export interface IndicatorDetail extends IndicatorSummary {
  actor_id?: string;
}

export interface IndicatorBrief {
  id: string;
  type: IndicatorType;
  value: string;
  confidence: number;
}

export interface IndicatorStats {
  type: string;
  count: number;
}

// ── Actors ──

export interface ActorSummary {
  id: string;
  name: string;
  aliases?: string[];
  first_seen?: string;
  last_seen?: string;
  // Synthetic ``ACTOR-XXXX`` rows minted by the attribution task.
  auto_generated: boolean;
  created_at: string;
}

export interface ActorDetail extends ActorSummary {
  description?: string;
  email_addresses?: string[];
  telegram_handles?: string[];
}

export interface ActorBrief {
  id: string;
  name: string;
}

// Actor stats — drives the rebuilt actor-detail Overview tab.
export interface ActorBrandCount {
  brand: string;
  count: number;
}

export interface ActorFamilyCount {
  family_id: string;
  family_name: string;
  count: number;
}

export interface ActorTimelineBucket {
  month: string; // YYYY-MM
  count: number;
}

export interface ActorIndicatorCount {
  type: string;
  value: string;
  count: number;
}

export interface ActorStats {
  kit_count: number;
  campaign_count: number;
  family_count: number;
  indicator_count: number;
  first_seen_computed: string | null;
  last_seen_computed: string | null;
  target_brand_distribution: ActorBrandCount[];
  family_distribution: ActorFamilyCount[];
  timeline: ActorTimelineBucket[];
  top_indicators: ActorIndicatorCount[];
}

// ── Campaigns ──

export interface CampaignSummary {
  id: string;
  name: string;
  target_brand?: string;
  start_date?: string;
  end_date?: string;
  created_at: string;
}

export interface CampaignDetail extends CampaignSummary {
  description?: string;
  auto_generated?: boolean;
  kits: KitSummary[];
  actors: ActorBrief[];
}

export interface CampaignBrief {
  id: string;
  name: string;
  target_brand?: string;
}

// Campaign stats — drives the rebuilt campaign-detail Overview tab.
export interface CampaignActorCount {
  actor_id: string;
  actor_name: string;
  count: number;
}

export interface CampaignFamilyCount {
  family_id: string;
  family_name: string;
  count: number;
}

export interface CampaignVictimCount {
  victim_id: string;
  email: string;
  display_name: string | null;
  type: string;
  count: number;
}

export interface CampaignYaraRuleCount {
  rule: string;
  count: number;
}

export interface CampaignTimelineBucket {
  month: string; // YYYY-MM
  count: number;
}

export interface CampaignIndicatorCount {
  type: string;
  value: string;
  count: number;
}

export interface CampaignVictimSourceBreakdown {
  source: string;
  count: number;
}

export interface CampaignStats {
  kit_count: number;
  actor_count: number;
  family_count: number;
  indicator_count: number;
  victim_count: number;
  first_seen_computed: string | null;
  last_seen_computed: string | null;
  top_actors: CampaignActorCount[];
  top_families: CampaignFamilyCount[];
  top_victims: CampaignVictimCount[];
  top_yara_rules: CampaignYaraRuleCount[];
  timeline: CampaignTimelineBucket[];
  top_indicators: CampaignIndicatorCount[];
  victim_source_breakdown: CampaignVictimSourceBreakdown[];
}

// ── Families ──

export interface FamilySummary {
  id: string;
  name: string;
  aliases?: string[];
  created_at: string;
}

export interface FamilyDetail extends FamilySummary {
  description?: string;
  actors: ActorBrief[];
}

export interface FamilyBrief {
  id: string;
  name: string;
}

// Family stats — mirrors darla/schemas/family.py FamilyStats; drives
// the family-detail Overview tab.
export interface FamilyBrandCount {
  brand: string;
  count: number;
}

export interface FamilyActorCount {
  actor_id: string;
  actor_name: string;
  count: number;
}

export interface FamilyYaraRuleCount {
  rule: string;
  count: number;
}

export interface FamilyTimelineBucket {
  month: string; // YYYY-MM
  count: number;
}

export interface FamilyIndicatorCount {
  type: string;
  value: string;
  count: number;
}

export interface FamilyStats {
  kit_count: number;
  actor_count: number;
  campaign_count: number;
  indicator_count: number;
  distinct_sha256_count: number;
  distinct_tlsh_count: number;
  first_seen_computed: string | null;
  last_seen_computed: string | null;
  target_brand_distribution: FamilyBrandCount[];
  top_actors: FamilyActorCount[];
  top_yara_rules: FamilyYaraRuleCount[];
  timeline: FamilyTimelineBucket[];
  top_indicators: FamilyIndicatorCount[];
}

// ── Analysis ──

export interface AnalysisResultBrief {
  id: string;
  analysis_type: AnalysisType;
  result_data?: Record<string, unknown>;
  duration_seconds?: number;
  files_processed?: number;
  error?: string;
  created_at: string;
}

export interface AnalysisResultDetail extends AnalysisResultBrief {
  kit_id: string;
  result_data: Record<string, unknown>;
  error?: string;
}

// ── Kit Content ──

export interface KitContentFile {
  filename: string;
  content: string;
  size: number;
  mime_type?: string;
  truncated: boolean;
}

export interface KitContentResponse {
  kit_id: string;
  files: KitContentFile[];
}

// ── Browser Artifacts ──

export interface ScreenshotItem {
  filename: string;
  stage: string;
  data_uri: string;
}

export interface ScreenshotsResponse {
  screenshots: ScreenshotItem[];
}

export interface NetworkEvent {
  url: string;
  method?: string;
  status?: number;
  resource_type?: string;
  content_type?: string;
  headers?: Record<string, string>;
  timestamp?: number;
  type: "request" | "response";
}

export interface NetworkLogResponse {
  events: NetworkEvent[];
  total: number;
}

export interface BrowserResourceItem {
  filename: string;
  size: number;
  mime_type?: string;
  content?: string;
  truncated: boolean;
}

export interface BrowserResourcesResponse {
  resources: BrowserResourceItem[];
}

export interface DeobfuscationPairItem {
  file: string;
  deob_file: string;
  layers: number;
  techniques: string[];
  original_content?: string;
  original_truncated: boolean;
  deob_content?: string;
  deob_truncated: boolean;
}

export interface DeobfuscationPreviewResponse {
  pairs: DeobfuscationPairItem[];
}

// ── PhishDiff ──

export interface DiffableKit {
  id: string;
  source_url: string;
  tlsh?: string;
  file_size?: number;
  status: string;
  created_at: string;
}

export interface DiffablePair {
  id: string;
  source_url: string;
  tlsh?: string;
  file_size?: number;
  distance: number;
  size_ratio: number;
  created_at: string;
}

export interface DiffPairGroup {
  domain: string;
  kits: DiffableKit[];
  pair_count: number;
}

export interface DiffPairGroupsResponse {
  groups: DiffPairGroup[];
  total: number;
}

export interface DiffKitContent {
  id: string;
  source_url: string;
  content: string;
  file_size?: number;
}

export interface DiffChangeCategory {
  category: string;
  count: number;
  examples: string[];
}

export interface DiffCompareSummary {
  structural_similarity: number;
  tlsh_distance?: number;
  change_categories: DiffChangeCategory[];
}

export interface DiffCompareResponse {
  kit_a: DiffKitContent;
  kit_b: DiffKitContent;
  summary: DiffCompareSummary;
  normalized: boolean;
}

// ── Health ──

export interface HealthResponse {
  status: "ok" | "degraded";
  services: Record<string, { status: "ok" | "error"; detail?: string }>;
}

// ── Task polling ──

export interface TaskStatusResponse {
  task_id: string;
  status: string;
  result?: Record<string, unknown>;
}

// ── PhishPrint (victims + monitored domains) ──

export type VictimType =
  | "user"
  | "exec"
  | "distro"
  | "shared_mailbox"
  | "service"
  | "unknown";

export type VictimObservationSource =
  | "oauth_state"
  | "oauth_login_hint"
  | "aitm_url_fragment"
  | "eml_to"
  | "eml_cc"
  | "eml_bcc"
  | "kit_content"
  | "other";

export interface MonitoredDomain {
  id: string;
  domain: string;
  description: string | null;
  created_at: string;
  updated_at: string;
}

export interface VictimSummary {
  id: string;
  email: string;
  domain: string;
  display_name: string | null;
  type: VictimType;
  first_seen: string | null;
  last_seen: string | null;
  created_at: string;
}

export interface VictimDetail extends VictimSummary {
  notes: string | null;
  updated_at: string;
}

export interface VictimObservationKit {
  id: string;
  source_url: string;
  status: string;
  sha256: string | null;
  chain_depth: number;
}

export interface VictimObservation {
  id: string;
  kit_id: string;
  source: VictimObservationSource;
  observed_at: string;
  kit: VictimObservationKit;
}

// ── YARA Playground ──

export interface YaraStatusResponse {
  available: boolean;
  rules_dir: string;
  builtin_rule_files: number;
  user_rule_files: number;
}

export interface YaraSaveRuleResponse {
  name: string;
  relative_path: string;
  size: number;
  compile_ok: boolean;
  compile_errors: YaraCompileError[];
}

export interface YaraCompileError {
  line: number | null;
  column: number | null;
  message: string;
}

export interface YaraCompileResult {
  ok: boolean;
  rules_count: number;
  errors: YaraCompileError[];
  warnings: string[];
}

export interface YaraStringMatch {
  identifier: string;
  offset: number;
  matched: string;
  context_before: string;
  context_after: string;
}

export interface YaraMatch {
  rule: string;
  namespace: string;
  tags: string[];
  meta: Record<string, string | number | boolean>;
  target_kit_id: string | null;
  target_path: string;
  target_size: number;
  target_mime: string | null;
  strings: YaraStringMatch[];
}

export interface YaraTargetError {
  target: string;
  error: string;
}

export interface YaraScanStats {
  files_scanned: number;
  files_skipped: number;
  bytes_scanned: number;
  duration_ms: number;
}

export interface YaraScanOptions {
  timeout_seconds?: number;
  max_files?: number;
  max_file_size_mb?: number;
  include_strings?: boolean;
  string_context_bytes?: number;
  extensions?: string[];
}

export interface YaraKitTarget {
  kit_id: string;
  relative_paths?: string[];
}

export interface YaraRawTarget {
  name: string;
  content?: string;
  content_b64?: string;
}

export interface YaraPlaygroundRequest {
  rule_source: string;
  kits?: YaraKitTarget[];
  raw?: YaraRawTarget[];
  options?: YaraScanOptions;
}

export interface YaraPlaygroundResponse {
  compile: YaraCompileResult;
  stats: YaraScanStats;
  matches: YaraMatch[];
  target_errors: YaraTargetError[];
}

export interface YaraRuleFileSummary {
  name: string;
  relative_path: string;
  size: number;
  rule_count: number;
  source: "builtin" | "third_party" | "user";
}

export interface YaraRuleFileSource {
  name: string;
  relative_path: string;
  source: "builtin" | "third_party" | "user";
  content: string;
}

export type YaraFileSource = "extracted" | "raw" | "browser_resource";

export interface YaraScannableFile {
  relative_path: string;
  size: number;
  mime_type: string | null;
  extension: string;
  scannable: boolean;
  source: YaraFileSource;
}

export interface YaraScannableFilesResponse {
  kit_id: string;
  files: YaraScannableFile[];
  total: number;
  scannable_count: number;
  counts_by_source: Partial<Record<YaraFileSource, number>>;
}
