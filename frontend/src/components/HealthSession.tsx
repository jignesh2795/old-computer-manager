import type { HealthSessionResponse, HealthStageResponse } from '../types/api'

interface HealthSessionProps {
  session: HealthSessionResponse | null
  stages: HealthStageResponse[] | null
}

const stageIcons: Record<string, string> = {
  completed: '[OK]',
  partial: '[PART]',
  failed: '[FAIL]',
  skipped: '[SKIP]',
  budget_exceeded: '[BUDGET]',
  running: '[...]',
  stale: '[STALE]',
}

export function HealthSession({ session, stages }: HealthSessionProps) {
  if (!session) {
    return (
      <div className="card">
        <div className="card-title">Latest Health Session</div>
        <div className="empty-state">
          No health sessions recorded yet. Run &quot;health run --profile quick&quot; to create one.
        </div>
      </div>
    )
  }

  const shownStages = stages ?? session.stages ?? []
  const totalMs = shownStages.reduce((sum, stage) => sum + (stage.duration_ms || 0), 0)

  return (
    <div className="card">
      <div className="card-title">Latest Health Session</div>
      <div className="row">
        <span className="row-label">Profile</span>
        <span className="row-value">{session.profile}</span>
      </div>
      <div className="row">
        <span className="row-label">Status</span>
        <span className="row-value">{session.status}</span>
      </div>
      <div className="row">
        <span className="row-label">Started</span>
        <span className="row-value">{session.started_at || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">Completed</span>
        <span className="row-value">{session.completed_at || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">Duration</span>
        <span className="row-value">{(totalMs / 1000).toFixed(1)}s</span>
      </div>

      <div style={{ marginTop: '8px' }}>
        <div className="row-label">Stages</div>
        {shownStages.map((stage) => (
          <div key={stage.stage_id} className="row">
            <span className="row-label">
              {stageIcons[stage.status] || '[?]'} {stage.stage_type}
            </span>
            <span className="row-value">{((stage.duration_ms || 0) / 1000).toFixed(2)}s</span>
          </div>
        ))}
        {shownStages
          .filter((stage) => stage.status !== 'completed' && stage.error)
          .map((stage) => (
            <div key={`err-${stage.stage_id}`} className="finding-meta">
              {stage.stage_type}: {stage.error}
            </div>
          ))}
      </div>

      <div className="row">
        <span className="row-label">Data quality</span>
        <span className="row-value">{session.data_quality}</span>
      </div>
      <div className="row">
        <span className="row-label">Discovery run</span>
        <span className="row-value">{session.discovery_run_id ?? 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">Evidence refs</span>
        <span className="row-value">{session.evidence_ids.length}</span>
      </div>
    </div>
  )
}
