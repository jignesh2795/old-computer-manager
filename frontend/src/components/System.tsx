import type { SystemResponse } from '../types/api'
import { formatBytes } from '../utils/format'

interface SystemProps {
  system: SystemResponse | null
}

export function System({ system }: SystemProps) {
  if (!system) {
    return (
      <div className="card">
        <div className="card-title">System</div>
        <div className="empty-state">Not available</div>
      </div>
    )
  }

  return (
    <div className="card">
      <div className="card-title">System</div>
      <div className="row">
        <span className="row-label">Hostname</span>
        <span className="row-value">{system.hostname || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">OS</span>
        <span className="row-value">{system.os_name || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">OS Version</span>
        <span className="row-value">{system.os_version || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">Architecture</span>
        <span className="row-value">{system.architecture || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">Manufacturer</span>
        <span className="row-value">{system.manufacturer || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">Model</span>
        <span className="row-value">{system.model || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">BIOS Vendor</span>
        <span className="row-value">{system.bios_vendor || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">BIOS Version</span>
        <span className="row-value">{system.bios_version || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">CPU</span>
        <span className="row-value">{system.cpu_name || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">CPU Cores (Physical)</span>
        <span className="row-value">{system.cpu_cores_physical ?? 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">CPU Cores (Logical)</span>
        <span className="row-value">{system.cpu_cores_logical ?? 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">RAM</span>
        <span className="row-value">{formatBytes(system.ram_total_bytes)}</span>
      </div>
    </div>
  )
}
