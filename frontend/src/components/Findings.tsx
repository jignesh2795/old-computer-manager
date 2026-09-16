import type { FindingsResponse } from '../types/api'
import { getSeverityColor } from '../utils/format'

interface FindingsProps {
  findings: FindingsResponse | null
}

export function Findings({ findings }: FindingsProps) {
  if (!findings) {
    return (
      <div className="card">
        <div className="card-title">Findings</div>
        <div className="empty-state">Not available</div>
      </div>
    )
  }

  if (!findings.findings_available) {
    return (
      <div className="card">
        <div className="card-title">Findings</div>
        <div className="empty-state">
          {findings.analysis_status === 'not_run'
            ? 'Analysis not run'
            : findings.analysis_status === 'failed'
            ? 'Analysis failed'
            : 'No findings available'}
        </div>
      </div>
    )
  }

  return (
    <div className="card">
      <div className="card-title">Findings</div>
      <div className="row">
        <span className="row-label">Status</span>
        <span className="row-value">
          <span className={`status-badge status-${getAnalysisStatusClass(findings.analysis_status)}`}>
            {findings.analysis_status || 'N/A'}
          </span>
        </span>
      </div>
      <div className="row">
        <span className="row-label">Critical</span>
        <span className="row-value" style={{ color: getSeverityColor('critical') }}>
          {findings.critical_count}
        </span>
      </div>
      <div className="row">
        <span className="row-label">Warning</span>
        <span className="row-value" style={{ color: getSeverityColor('warning') }}>
          {findings.warning_count}
        </span>
      </div>
      <div className="row">
        <span className="row-label">Info</span>
        <span className="row-value" style={{ color: getSeverityColor('info') }}>
          {findings.info_count}
        </span>
      </div>

      {findings.findings.length > 0 && (
        <div style={{ marginTop: '12px' }}>
          {findings.findings.map((finding, index) => (
            <div
              key={finding.finding_id || index}
              className={`finding-card finding-${finding.severity}`}
            >
              <div className="finding-title">{finding.title}</div>
              <div className="finding-meta">
                <span className={`status-badge status-${finding.severity}`}>
                  {finding.severity}
                </span>
                {' '}&middot; {finding.analyzer}
              </div>
              <div className="finding-message">{finding.message}</div>
              {finding.recommendation && (
                <div className="finding-recommendation">
                  {finding.recommendation}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
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
