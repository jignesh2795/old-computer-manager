import type { StorageResponse, FileAnalysisResponse } from '../types/api'
import { formatBytes, formatPercent, getStatusColor } from '../utils/format'

interface StorageProps {
  storage: StorageResponse | null
  fileAnalysis: FileAnalysisResponse | null
}

export function Storage({ storage, fileAnalysis }: StorageProps) {
  if (!storage) {
    return (
      <div className="card">
        <div className="card-title">Storage</div>
        <div className="empty-state">Not available</div>
      </div>
    )
  }

  return (
    <div className="card">
      <div className="card-title">Storage</div>
      <div className="row">
        <span className="row-label">Partitions</span>
        <span className="row-value">{storage.count}</span>
      </div>
      <div className="row">
        <span className="row-label">Total Capacity</span>
        <span className="row-value">{formatBytes(storage.total_capacity_bytes)}</span>
      </div>
      <div className="row">
        <span className="row-label">Total Free</span>
        <span className="row-value">{formatBytes(storage.total_free_bytes)}</span>
      </div>

      {storage.partitions.length > 0 && (
        <div style={{ marginTop: '12px' }}>
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>FS</th>
                <th>Total</th>
                <th>Free</th>
                <th>Used</th>
                <th style={{ width: '100px' }}>Usage</th>
              </tr>
            </thead>
            <tbody>
              {storage.partitions.map((partition) => (
                <tr key={partition.device}>
                  <td>{partition.device || 'N/A'}</td>
                  <td>{partition.filesystem || 'N/A'}</td>
                  <td>{formatBytes(partition.total_bytes)}</td>
                  <td>{formatBytes(partition.free_bytes)}</td>
                  <td>{formatBytes(partition.used_bytes)}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <span style={{ color: getStatusColor(partition.status || 'normal') }}>
                        {formatPercent(partition.usage_percent)}
                      </span>
                    </div>
                    <div className="progress-bar">
                      <div
                        className={`progress-fill ${getProgressClass(partition.usage_percent)}`}
                        style={{ width: `${partition.usage_percent || 0}%` }}
                      />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {fileAnalysis && fileAnalysis.available && (
        <div style={{ marginTop: '12px', borderTop: '1px solid var(--color-border)', paddingTop: '8px' }}>
          <div className="row">
            <span className="row-label">Largest Files</span>
            <span className="row-value">{fileAnalysis.largest_files.length}</span>
          </div>
          <div className="row">
            <span className="row-label">Duplicate Groups</span>
            <span className="row-value">{fileAnalysis.duplicate_groups}</span>
          </div>
        </div>
      )}
    </div>
  )
}

function getProgressClass(percent: number | null): string {
  if (percent === null) return 'progress-normal'
  if (percent >= 90) return 'progress-critical'
  if (percent >= 75) return 'progress-warning'
  return 'progress-normal'
}
