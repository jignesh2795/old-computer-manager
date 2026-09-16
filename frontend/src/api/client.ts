// API service layer for consuming the existing FastAPI backend
// All endpoints are read-only GET requests

import type {
  HealthResponse,
  ReportResponse,
  FindingsResponse,
  StorageResponse,
  BatteryResponse,
  FileAnalysisResponse,
  RemediationActionsResponse,
  SystemResponse,
  AdvisoryResponse,
  HistorySummaryResponse,
} from '../types/api'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000'

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`)
  if (!response.ok) {
    throw new Error(`API error: ${response.status} ${response.statusText}`)
  }
  return response.json()
}

export const api = {
  health: () => fetchJson<HealthResponse>('/health'),
  report: () => fetchJson<ReportResponse>('/api/v1/report'),
  findings: () => fetchJson<FindingsResponse>('/api/v1/findings'),
  storage: () => fetchJson<StorageResponse>('/api/v1/storage'),
  battery: () => fetchJson<BatteryResponse>('/api/v1/battery'),
  fileAnalysis: () => fetchJson<FileAnalysisResponse>('/api/v1/file-analysis'),
  remediationActions: () => fetchJson<RemediationActionsResponse>('/api/v1/remediation/actions'),
  system: () => fetchJson<SystemResponse>('/api/v1/system'),
  advisory: () => fetchJson<AdvisoryResponse>('/api/v1/ai/advisory'),
  history: () => fetchJson<HistorySummaryResponse>('/api/v1/history/summary'),
}
