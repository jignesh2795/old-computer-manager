// TypeScript types matching the existing FastAPI API schemas
// Source of truth: app/api/schemas.py

export interface HealthResponse {
  status: string
  service: string
  version: string
}

export interface SystemResponse {
  hostname: string | null
  os_name: string | null
  os_version: string | null
  architecture: string | null
  manufacturer: string | null
  model: string | null
  bios_vendor: string | null
  bios_version: string | null
  cpu_name: string | null
  cpu_cores_physical: number | null
  cpu_cores_logical: number | null
  ram_total_bytes: number | null
}

export interface StoragePartitionResponse {
  device: string | null
  filesystem: string | null
  total_bytes: number | null
  used_bytes: number | null
  free_bytes: number | null
  usage_percent: number | null
  status: string | null
}

export interface StorageResponse {
  partitions: StoragePartitionResponse[]
  count: number
  total_capacity_bytes: number | null
  total_free_bytes: number | null
}

export interface BatteryResponse {
  available: boolean | null
  status: string | null
  charge_percent: number | null
  plugged_in: boolean | null
  design_capacity_mwh: number | null
  full_charge_capacity_mwh: number | null
  remaining_capacity_mwh: number | null
  health_percent: number | null
  wear_percent: number | null
  health_status: string | null
  cycle_count: number | null
  manufacturer: string | null
  battery_name: string | null
  baseline_status: string
}

export interface FindingResponse {
  finding_id: string | null
  analyzer: string
  severity: string
  title: string
  message: string
  evidence: Record<string, unknown> | null
  recommendation: string | null
  created_at: string | null
}

export interface FindingsResponse {
  analysis_status: string | null
  findings_available: boolean
  findings_count: number | null
  critical_count: number
  warning_count: number
  info_count: number
  findings: FindingResponse[]
}

export interface FileAnalysisResponse {
  available: boolean
  scan_root: string | null
  scan_timestamp: string | null
  files_examined: number
  directories_examined: number
  bytes_examined: number
  files_skipped: number
  symlinks_skipped: number
  excluded_items: number
  inaccessible_items: number
  largest_files: Array<Record<string, unknown>>
  largest_directories: Array<Record<string, unknown>>
  file_type_summary: Array<Record<string, unknown>>
  duplicate_groups: number
  potential_duplicate_bytes: number
}

export interface RemediationActionResponse {
  action_id: string
  name: string
  risk_level: string
  reversible: boolean
  requires_admin: boolean
  preview_available: boolean
  rollback_available: boolean
  real_execution_exists: boolean
}

export interface RemediationActionsResponse {
  actions: RemediationActionResponse[]
  count: number
}

export interface ReportResponse {
  schema_version: string
  generated_at: string
  discovery_run_id: number | null
  discovery_status: string | null
  analysis_status: string | null
  findings_available: boolean
  findings_count: number | null
  system: SystemResponse
  storage: StorageResponse
  battery: BatteryResponse
  findings: FindingsResponse
  software: Record<string, unknown>
  startup: Record<string, unknown>
  processes: Record<string, unknown>
  services: Record<string, unknown>
  scheduled_tasks: Record<string, unknown>
  file_analysis: FileAnalysisResponse
  remediation: RemediationActionsResponse
  diagnostics: DiagnosticsSummaryResponse
  errors: Array<Record<string, unknown>>
}

export interface ObservationResponse {
  title: string
  evidence: string
  source: string
  severity: string
  confidence: string
}

export interface RecommendationResponse {
  title: string
  rationale: string
  related_finding_ids: string[]
  related_action_ids: string[]
  risk_level: string
  requires_confirmation: boolean
  executable: boolean
}

export interface UncertaintyResponse {
  description: string
  impact: string
}

export interface LimitationResponse {
  description: string
}

export interface AdvisoryMetadataResponse {
  provider: string
  model: string
  prompt_version: string
  generated_at: string
}

export interface AdvisoryHistoricalSummaryResponse {
  runs_considered: number
  observations_used: number
  trends_count: number
  baselines_established: number
  recurring_findings_count: number
  anomalies_count: number
  data_quality_issues: number
  limited_by: string
}

export interface AdvisoryResponse {
  schema_version: string
  generated_at: string
  report_run_id: number | null
  analysis_status: string | null
  summary: string
  observations: ObservationResponse[]
  recommendations: RecommendationResponse[]
  uncertainties: UncertaintyResponse[]
  limitations: LimitationResponse[]
  metadata: AdvisoryMetadataResponse
  historical_summary: AdvisoryHistoricalSummaryResponse | null
}

// Historical analysis types

export interface TrendResponse {
  metric_name: string
  observations_count: number
  first_value: number | null
  latest_value: number | null
  minimum: number | null
  maximum: number | null
  delta_absolute: number | null
  delta_percent: number | null
  direction: string
  first_timestamp: string | null
  latest_timestamp: string | null
}

export interface BaselineResponse {
  metric_name: string
  baseline_run_id: number | null
  baseline_timestamp: string | null
  baseline_value: number | null
  current_value: number | null
  delta: number | null
  delta_percent: number | null
  baseline_status: string
}

export interface RecurringFindingResponse {
  analyzer: string
  severity: string
  title: string
  first_seen: string | null
  last_seen: string | null
  occurrence_count: number
  run_ids: number[]
}

export interface AnomalyResponse {
  metric_name: string
  severity: string
  title: string
  message: string
  evidence: Record<string, unknown>
  first_detected: string | null
  last_detected: string | null
  occurrence_count: number
}

export interface DataQualityResponse {
  metric_name: string
  total_observations: number
  valid_observations: number
  missing_count: number
  not_supported_count: number
  failed_count: number
}

export interface HistorySummaryResponse {
  runs_considered: number
  observations_available: number
  run_ids: number[]
  trends: TrendResponse[]
  baseline: BaselineResponse[]
  recurring_findings: RecurringFindingResponse[]
  anomalies: AnomalyResponse[]
  data_quality: DataQualityResponse[]
}

// Diagnostic types

export interface DiagnosticResultResponse {
  diagnostic_id: string
  category: string
  status: string
  title: string
  summary: string
  evidence: Record<string, unknown>
  source: string
  collected_at: string
  limitations: string[]
  errors: string[]
}

export interface DiagnosticsSummaryResponse {
  available: boolean
  run_id: number | null
  status: string | null
  result_count: number
  categories: string[]
  status_counts: Record<string, number>
  results: DiagnosticResultResponse[]
}
