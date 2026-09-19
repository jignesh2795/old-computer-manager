import type { DiagnosticsSummaryResponse } from '../types/api'
import { getStatusColor } from '../utils/format'

interface DiagnosticsProps {
  diagnostics: DiagnosticsSummaryResponse | null
}

export function Diagnostics({ diagnostics }: DiagnosticsProps) {
  if (!diagnostics || !diagnostics.available) {
    return (
      <div className="card">
        <div className="card-title">Advanced Diagnostics</div>
        <div className="empty-state">No diagnostic data available. Run diagnostics from the CLI.</div>
      </div>
    )
  }

  const statusIcons: Record<string, string> = {
    ok: '[OK]',
    warning: '[WARN]',
    critical: '[CRIT]',
    unavailable: '[N/A]',
    not_supported: '[N/S]',
    failed: '[FAIL]',
  }

  return (
    <div className="card">
      <div className="card-title">Advanced Diagnostics</div>
      <div className="row">
        <span className="row-label">Status</span>
        <span className="row-value" style={{ color: diagnostics.status === 'completed' ? 'var(--color-normal)' : 'var(--color-warning)' }}>
          {diagnostics.status || 'unknown'}
        </span>
      </div>
      <div className="row">
        <span className="row-label">Results</span>
        <span className="row-value">{diagnostics.result_count}</span>
      </div>
      <div className="row">
        <span className="row-label">Categories</span>
        <span className="row-value">{diagnostics.categories.join(', ') || 'none'}</span>
      </div>

      {Object.keys(diagnostics.status_counts).length > 0 && (
        <div style={{ marginTop: '8px' }}>
          <div className="row-label">Status Summary</div>
          {Object.entries(diagnostics.status_counts).map(([status, count]) => (
            <div key={status} className="row">
              <span className="row-label" style={{ color: getStatusColor(status) }}>
                {statusIcons[status] || '[?]'} {status}
              </span>
              <span className="row-value">{count}</span>
            </div>
          ))}
        </div>
      )}

      {diagnostics.results.length > 0 && (
        <div style={{ marginTop: '12px' }}>
          {diagnostics.results.map((result) => (
            <div
              key={result.diagnostic_id}
              className="finding-card"
              style={{ borderLeftColor: getStatusColor(result.status) }}
            >
              <div className="finding-header">
                <span className="finding-title">{statusIcons[result.status] || '[?]'} {result.title}</span>
                <span className="finding-severity" style={{ color: getStatusColor(result.status) }}>
                  {result.category}
                </span>
              </div>
              <div className="finding-message">{result.summary}</div>
              {result.source && (
                <div className="finding-meta">Source: {result.source}</div>
              )}
              {result.limitations.length > 0 && result.limitations.filter(Boolean).length > 0 && (
                <div className="finding-meta">
                  {result.limitations.filter(Boolean).map((lim, i) => (
                    <div key={i}>Note: {lim}</div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <div style={{ marginTop: '12px', fontSize: '0.85em', color: 'var(--color-muted)' }}>
        Diagnostics identify evidence and observations; they do not perform repairs.
      </div>
    </div>
  )
}
