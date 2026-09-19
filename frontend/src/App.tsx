import { useState, useCallback } from 'react'
import './App.css'
import { api } from './api/client'
import type {
  ReportResponse,
  AdvisoryResponse,
  FindingsResponse,
  StorageResponse,
  BatteryResponse,
  FileAnalysisResponse,
  RemediationActionsResponse,
  SystemResponse,
  HistorySummaryResponse,
  DiagnosticsSummaryResponse,
} from './types/api'
import { Overview } from './components/Overview'
import { Findings } from './components/Findings'
import { Storage } from './components/Storage'
import { Battery } from './components/Battery'
import { FileAnalysis } from './components/FileAnalysis'
import { AiAdvisory } from './components/AiAdvisory'
import { Remediation } from './components/Remediation'
import { System } from './components/System'
import { Historical } from './components/Historical'
import { Diagnostics } from './components/Diagnostics'

interface DashboardData {
  report: ReportResponse | null
  advisory: AdvisoryResponse | null
  findings: FindingsResponse | null
  storage: StorageResponse | null
  battery: BatteryResponse | null
  fileAnalysis: FileAnalysisResponse | null
  remediation: RemediationActionsResponse | null
  system: SystemResponse | null
  history: HistorySummaryResponse | null
  diagnostics: DiagnosticsSummaryResponse | null
}

function App() {
  const [data, setData] = useState<DashboardData>({
    report: null,
    advisory: null,
    findings: null,
    storage: null,
    battery: null,
    fileAnalysis: null,
    remediation: null,
    system: null,
    history: null,
    diagnostics: null,
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [lastFetch, setLastFetch] = useState<string | null>(null)

  const fetchData = useCallback(async () => {
    setLoading(true)
    setError(null)

    try {
      const [
        report,
        advisory,
        findings,
        storage,
        battery,
        fileAnalysis,
        remediation,
        system,
        history,
        diagnostics,
      ] = await Promise.all([
        api.report().catch(() => null),
        api.advisory().catch(() => null),
        api.findings().catch(() => null),
        api.storage().catch(() => null),
        api.battery().catch(() => null),
        api.fileAnalysis().catch(() => null),
        api.remediationActions().catch(() => null),
        api.system().catch(() => null),
        api.history().catch(() => null),
        api.diagnosticsSummary().catch(() => null),
      ])

      setData({
        report,
        advisory,
        findings,
        storage,
        battery,
        fileAnalysis,
        remediation,
        system,
        history,
        diagnostics,
      })
      setLastFetch(new Date().toLocaleTimeString())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch data')
    } finally {
      setLoading(false)
    }
  }, [])

  return (
    <div className="dashboard">
      <header className="header">
        <h1>Old Computer Manager</h1>
        <div className="header-meta">
          {lastFetch && <span>Last updated: {lastFetch}</span>}
          <button
            className="refresh-btn"
            onClick={fetchData}
            disabled={loading}
          >
            {loading ? 'Loading...' : 'Refresh'}
          </button>
        </div>
      </header>

      {error && <div className="error-state">{error}</div>}

      {!data.report && !loading && !error && (
        <div className="empty-state">
          Click Refresh to load dashboard data
        </div>
      )}

      {data.report && (
        <div className="grid">
          <Overview
            system={data.system}
            storage={data.storage}
            battery={data.battery}
            report={data.report}
          />
          <Findings findings={data.findings} />
          <Storage storage={data.storage} fileAnalysis={data.fileAnalysis} />
          <Battery battery={data.battery} />
          <System system={data.system} />
          <AiAdvisory advisory={data.advisory} />
          <Remediation remediation={data.remediation} />
          <FileAnalysis fileAnalysis={data.fileAnalysis} />
          <Historical history={data.history} />
          <Diagnostics diagnostics={data.diagnostics} />
        </div>
      )}
    </div>
  )
}

export default App
