import type { FileAnalysisResponse } from '../types/api'
import { formatBytes } from '../utils/format'

interface FileAnalysisProps {
  fileAnalysis: FileAnalysisResponse | null
}

export function FileAnalysis({ fileAnalysis }: FileAnalysisProps) {
  if (!fileAnalysis || !fileAnalysis.available) {
    return (
      <div className="card">
        <div className="card-title">File Analysis</div>
        <div className="empty-state">Not available</div>
      </div>
    )
  }

  return (
    <div className="card">
      <div className="card-title">File Analysis</div>
      <div className="row">
        <span className="row-label">Scan Root</span>
        <span className="row-value" style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
          {fileAnalysis.scan_root || 'N/A'}
        </span>
      </div>
      <div className="row">
        <span className="row-label">Scan Time</span>
        <span className="row-value">{fileAnalysis.scan_timestamp || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">Files Examined</span>
        <span className="row-value">{fileAnalysis.files_examined}</span>
      </div>
      <div className="row">
        <span className="row-label">Directories</span>
        <span className="row-value">{fileAnalysis.directories_examined}</span>
      </div>
      <div className="row">
        <span className="row-label">Bytes Examined</span>
        <span className="row-value">{formatBytes(fileAnalysis.bytes_examined)}</span>
      </div>
      <div className="row">
        <span className="row-label">Files Skipped</span>
        <span className="row-value">{fileAnalysis.files_skipped}</span>
      </div>
      <div className="row">
        <span className="row-label">Symlinks Skipped</span>
        <span className="row-value">{fileAnalysis.symlinks_skipped}</span>
      </div>
      <div className="row">
        <span className="row-label">Excluded Items</span>
        <span className="row-value">{fileAnalysis.excluded_items}</span>
      </div>
      <div className="row">
        <span className="row-label">Inaccessible</span>
        <span className="row-value">{fileAnalysis.inaccessible_items}</span>
      </div>
      <div className="row">
        <span className="row-label">Duplicate Groups</span>
        <span className="row-value">{fileAnalysis.duplicate_groups}</span>
      </div>
      <div className="row">
        <span className="row-label">Potential Savings</span>
        <span className="row-value">{formatBytes(fileAnalysis.potential_duplicate_bytes)}</span>
      </div>

      {fileAnalysis.largest_files.length > 0 && (
        <div style={{ marginTop: '12px' }}>
          <div className="advisory-section-title">Largest Files</div>
          <table>
            <thead>
              <tr>
                <th>Path</th>
                <th>Size</th>
              </tr>
            </thead>
            <tbody>
              {fileAnalysis.largest_files.map((file, index) => (
                <tr key={index}>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                    {String(file.path || 'N/A')}
                  </td>
                  <td>{formatBytes(Number(file.size || 0))}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {fileAnalysis.largest_directories.length > 0 && (
        <div style={{ marginTop: '12px' }}>
          <div className="advisory-section-title">Largest Directories</div>
          <table>
            <thead>
              <tr>
                <th>Path</th>
                <th>Size</th>
              </tr>
            </thead>
            <tbody>
              {fileAnalysis.largest_directories.map((dir, index) => (
                <tr key={index}>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                    {String(dir.path || 'N/A')}
                  </td>
                  <td>{formatBytes(Number(dir.size || 0))}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
