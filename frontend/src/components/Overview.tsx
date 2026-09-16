import type { SystemResponse, StorageResponse, BatteryResponse, ReportResponse } from '../types/api'
import { formatBytes } from '../utils/format'

interface OverviewProps {
  system: SystemResponse | null
  storage: StorageResponse | null
  battery: BatteryResponse | null
  report: ReportResponse | null
}

export function Overview({ system, storage, battery, report }: OverviewProps) {
  return (
    <div className="card card-full">
      <div className="card-title">Overview</div>
      <div className="grid" style={{ gap: '8px' }}>
        <div>
          <div className="row">
            <span className="row-label">Hostname</span>
            <span className="row-value">{system?.hostname || 'N/A'}</span>
          </div>
          <div className="row">
            <span className="row-label">OS</span>
            <span className="row-value">
              {system?.os_name && system?.os_version
                ? `${system.os_name} ${system.os_version}`
                : 'N/A'}
            </span>
          </div>
          <div className="row">
            <span className="row-label">Model</span>
            <span className="row-value">{system?.model || 'N/A'}</span>
          </div>
        </div>
        <div>
          <div className="row">
            <span className="row-label">CPU</span>
            <span className="row-value">{system?.cpu_name || 'N/A'}</span>
          </div>
          <div className="row">
            <span className="row-label">RAM</span>
            <span className="row-value">{formatBytes(system?.ram_total_bytes)}</span>
          </div>
          <div className="row">
            <span className="row-label">Architecture</span>
            <span className="row-value">{system?.architecture || 'N/A'}</span>
          </div>
        </div>
        <div>
          <div className="row">
            <span className="row-label">Storage</span>
            <span className="row-value">
              {storage?.count || 0} partition(s)
            </span>
          </div>
          <div className="row">
            <span className="row-label">Total Capacity</span>
            <span className="row-value">{formatBytes(storage?.total_capacity_bytes)}</span>
          </div>
          <div className="row">
            <span className="row-label">Battery</span>
            <span className="row-value">
              {battery?.available ? `${battery.status || 'N/A'}` : 'Not available'}
            </span>
          </div>
        </div>
        <div>
          <div className="row">
            <span className="row-label">Discovery Run</span>
            <span className="row-value">
              #{report?.discovery_run_id || 'N/A'} ({report?.discovery_status || 'N/A'})
            </span>
          </div>
          <div className="row">
            <span className="row-label">Analysis</span>
            <span className="row-value">
              <span className={`status-badge status-${getAnalysisStatusClass(report?.analysis_status)}`}>
                {report?.analysis_status || 'Not run'}
              </span>
            </span>
          </div>
          <div className="row">
            <span className="row-label">Findings</span>
            <span className="row-value">
              {report?.findings_count !== null && report?.findings_count !== undefined
                ? report.findings_count
                : 'Not analyzed'}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

function getAnalysisStatusClass(status: string | null | undefined): string {
  switch (status) {
    case 'completed':
      return 'normal'
    case 'failed':
      return 'critical'
    case 'partial':
      return 'warning'
    default:
      return 'muted'
  }
}
