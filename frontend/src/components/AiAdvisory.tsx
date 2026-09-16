import type { AdvisoryResponse } from '../types/api'

interface AiAdvisoryProps {
  advisory: AdvisoryResponse | null
}

export function AiAdvisory({ advisory }: AiAdvisoryProps) {
  if (!advisory) {
    return (
      <div className="card">
        <div className="card-title">AI Advisory</div>
        <div className="empty-state">Not available</div>
      </div>
    )
  }

  return (
    <div className="card">
      <div className="card-title">AI Advisory</div>
      <div className="row">
        <span className="row-label">Provider</span>
        <span className="row-value">{advisory.metadata.provider || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">Model</span>
        <span className="row-value">{advisory.metadata.model || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">Generated</span>
        <span className="row-value">{advisory.generated_at || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">Analysis Status</span>
        <span className="row-value">{advisory.analysis_status || 'N/A'}</span>
      </div>

      {advisory.summary && (
        <div style={{ marginTop: '12px', padding: '8px', background: 'var(--color-bg)', borderRadius: '4px' }}>
          <div className="advisory-section-title">Summary</div>
          <div style={{ fontSize: '0.875rem' }}>{advisory.summary}</div>
        </div>
      )}

      {advisory.observations.length > 0 && (
        <div className="advisory-section" style={{ marginTop: '12px' }}>
          <div className="advisory-section-title">Observations</div>
          {advisory.observations.map((obs, index) => (
            <div key={index} className="advisory-item">
              <span className={`status-badge status-${obs.severity}`}>
                {obs.severity}
              </span>
              {' '}
              <strong>{obs.title}</strong>
              <div style={{ fontSize: '0.875rem', color: 'var(--color-muted)', marginTop: '4px' }}>
                {obs.evidence}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--color-muted)', marginTop: '2px' }}>
                Source: {obs.source} | Confidence: {obs.confidence}
              </div>
            </div>
          ))}
        </div>
      )}

      {advisory.recommendations.length > 0 && (
        <div className="advisory-section" style={{ marginTop: '12px' }}>
          <div className="advisory-section-title">Recommendations</div>
          {advisory.recommendations.map((rec, index) => (
            <div key={index} className="advisory-item">
              <strong>{rec.title}</strong>
              <div style={{ fontSize: '0.875rem', marginTop: '4px' }}>
                {rec.rationale}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--color-muted)', marginTop: '4px' }}>
                Risk: {rec.risk_level} | Requires confirmation: {rec.requires_confirmation ? 'Yes' : 'No'}
                {rec.executable && (
                  <span style={{ color: 'var(--color-critical)' }}> | Executable</span>
                )}
              </div>
              {rec.related_action_ids.length > 0 && (
                <div style={{ fontSize: '0.75rem', color: 'var(--color-muted)', marginTop: '2px' }}>
                  Related actions: {rec.related_action_ids.join(', ')}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {advisory.uncertainties.length > 0 && (
        <div className="advisory-section" style={{ marginTop: '12px' }}>
          <div className="advisory-section-title">Uncertainties</div>
          {advisory.uncertainties.map((unc, index) => (
            <div key={index} className="advisory-item">
              <strong>{unc.description}</strong>
              <div style={{ fontSize: '0.875rem', color: 'var(--color-muted)', marginTop: '4px' }}>
                Impact: {unc.impact}
              </div>
            </div>
          ))}
        </div>
      )}

      {advisory.limitations.length > 0 && (
        <div className="advisory-section" style={{ marginTop: '12px' }}>
          <div className="advisory-section-title">Limitations</div>
          {advisory.limitations.map((lim, index) => (
            <div key={index} className="advisory-item">
              {lim.description}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
