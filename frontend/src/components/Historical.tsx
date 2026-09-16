import type { HistorySummaryResponse } from '../types/api'

interface HistoricalProps {
  history: HistorySummaryResponse | null
}

function getDirectionColor(direction: string): string {
  switch (direction) {
    case 'increasing': return '#f59e0b'
    case 'decreasing': return '#3b82f6'
    case 'stable': return '#10b981'
    default: return '#6b7280'
  }
}

function getStatusColor(status: string): string {
  switch (status) {
    case 'improved': return '#10b981'
    case 'degraded': return '#ef4444'
    case 'unchanged': return '#6b7280'
    case 'established': return '#3b82f6'
    case 'unavailable': return '#9ca3af'
    default: return '#6b7280'
  }
}

function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical': return '#ef4444'
    case 'warning': return '#f59e0b'
    case 'info': return '#3b82f6'
    default: return '#6b7280'
  }
}

export function Historical({ history }: HistoricalProps) {
  if (!history) {
    return (
      <div className="card">
        <h2>Historical Trends</h2>
        <div className="empty-state">No historical data available</div>
      </div>
    )
  }

  if (history.runs_considered === 0) {
    return (
      <div className="card">
        <h2>Historical Trends</h2>
        <div className="empty-state">
          No completed discovery runs found. Run discovery first to collect historical data.
        </div>
      </div>
    )
  }

  return (
    <div className="card">
      <h2>Historical Trends</h2>
      <div className="info-row">
        <span className="label">Runs analyzed:</span>
        <span>{history.runs_considered}</span>
      </div>
      <div className="info-row">
        <span className="label">Observations:</span>
        <span>{history.observations_available}</span>
      </div>

      {history.trends.length > 0 && (
        <>
          <h3>Trends</h3>
          <div className="trends-list">
            {history.trends.slice(0, 10).map((trend) => (
              <div key={trend.metric_name} className="trend-item">
                <div className="trend-header">
                  <span
                    className="trend-direction"
                    style={{ color: getDirectionColor(trend.direction) }}
                  >
                    {trend.direction === 'increasing' ? '\u2191' :
                     trend.direction === 'decreasing' ? '\u2193' : '\u2192'}
                  </span>
                  <span className="trend-metric">{trend.metric_name}</span>
                  <span className="trend-count">({trend.observations_count} obs)</span>
                </div>
                {trend.delta_percent !== null && (
                  <div className="trend-delta">
                    Delta: {trend.delta_percent > 0 ? '+' : ''}{trend.delta_percent.toFixed(1)}%
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}

      {history.baseline.length > 0 && (
        <>
          <h3>Baseline Comparison</h3>
          <div className="baseline-list">
            {history.baseline.slice(0, 10).map((b) => (
              <div key={b.metric_name} className="baseline-item">
                <div className="baseline-header">
                  <span
                    className="baseline-status"
                    style={{ color: getStatusColor(b.baseline_status) }}
                  >
                    {b.baseline_status}
                  </span>
                  <span className="baseline-metric">{b.metric_name}</span>
                </div>
                {b.delta !== null && (
                  <div className="baseline-delta">
                    Delta: {b.delta > 0 ? '+' : ''}{b.delta.toFixed(2)}
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}

      {history.recurring_findings.length > 0 && (
        <>
          <h3>Recurring Findings</h3>
          <div className="recurring-list">
            {history.recurring_findings.slice(0, 5).map((r, i) => (
              <div key={`${r.analyzer}-${r.title}-${i}`} className="recurring-item">
                <div className="recurring-header">
                  <span
                    className="recurring-severity"
                    style={{ color: getSeverityColor(r.severity) }}
                  >
                    [{r.severity.toUpperCase()}]
                  </span>
                  <span className="recurring-title">{r.title}</span>
                </div>
                <div className="recurring-meta">
                  {r.occurrence_count} runs | {r.analyzer}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {history.anomalies.length > 0 && (
        <>
          <h3>Anomalies</h3>
          <div className="anomalies-list">
            {history.anomalies.slice(0, 5).map((a, i) => (
              <div key={`${a.metric_name}-${i}`} className="anomaly-item">
                <div className="anomaly-header">
                  <span
                    className="anomaly-severity"
                    style={{ color: getSeverityColor(a.severity) }}
                  >
                    [{a.severity.toUpperCase()}]
                  </span>
                  <span className="anomaly-title">{a.title}</span>
                </div>
                <div className="anomaly-message">{a.message}</div>
              </div>
            ))}
          </div>
        </>
      )}

      <div className="disclaimer">
        Descriptive historical analysis, not predictive failure forecasting.
      </div>
    </div>
  )
}
