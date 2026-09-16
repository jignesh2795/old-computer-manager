import type { RemediationActionsResponse } from '../types/api'
import { getRiskColor } from '../utils/format'

interface RemediationProps {
  remediation: RemediationActionsResponse | null
}

export function Remediation({ remediation }: RemediationProps) {
  if (!remediation) {
    return (
      <div className="card">
        <div className="card-title">Remediation Actions</div>
        <div className="empty-state">Not available</div>
      </div>
    )
  }

  return (
    <div className="card">
      <div className="card-title">Remediation Actions</div>
      <div className="row">
        <span className="row-label">Registered Actions</span>
        <span className="row-value">{remediation.count}</span>
      </div>

      {remediation.actions.length > 0 && (
        <div style={{ marginTop: '12px' }}>
          {remediation.actions.map((action) => (
            <div key={action.action_id} className="action-card">
              <div className="action-header">
                <span className="action-name">{action.name}</span>
                <span
                  className="tag"
                  style={{ color: getRiskColor(action.risk_level) }}
                >
                  {action.risk_level}
                </span>
              </div>
              <div className="action-id">{action.action_id}</div>
              <div className="action-meta">
                {action.reversible ? (
                  <span className="tag tag-reversible">Reversible</span>
                ) : (
                  <span className="tag tag-irreversible">Irreversible</span>
                )}
                {action.requires_admin && (
                  <span className="tag tag-admin">Requires Admin</span>
                )}
                {action.preview_available && (
                  <span>Preview available</span>
                )}
                {action.rollback_available && (
                  <span>Rollback available</span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      <div style={{ marginTop: '12px', padding: '8px', background: '#f5f5f5', borderRadius: '4px', fontSize: '0.875rem', color: 'var(--color-muted)' }}>
        This section is informational only. No actions can be executed from this dashboard.
      </div>
    </div>
  )
}
