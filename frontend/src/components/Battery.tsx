import type { BatteryResponse } from '../types/api'
import { formatPercent } from '../utils/format'

interface BatteryProps {
  battery: BatteryResponse | null
}

export function Battery({ battery }: BatteryProps) {
  if (!battery) {
    return (
      <div className="card">
        <div className="card-title">Battery</div>
        <div className="empty-state">Not available</div>
      </div>
    )
  }

  if (!battery.available) {
    return (
      <div className="card">
        <div className="card-title">Battery</div>
        <div className="empty-state">Not available</div>
      </div>
    )
  }

  return (
    <div className="card">
      <div className="card-title">Battery</div>
      <div className="row">
        <span className="row-label">Status</span>
        <span className="row-value">
          <span className={`status-badge status-${getStatusClass(battery.status)}`}>
            {battery.status || 'N/A'}
          </span>
        </span>
      </div>
      <div className="row">
        <span className="row-label">Charge</span>
        <span className="row-value">{formatPercent(battery.charge_percent)}</span>
      </div>
      <div className="row">
        <span className="row-label">Plugged In</span>
        <span className="row-value">{battery.plugged_in ? 'Yes' : 'No'}</span>
      </div>
      <div className="row">
        <span className="row-label">Health</span>
        <span className="row-value">
          {battery.health_percent !== null
            ? `${battery.health_percent.toFixed(1)}%`
            : battery.health_status || 'unavailable'}
        </span>
      </div>
      {battery.wear_percent !== null && (
        <div className="row">
          <span className="row-label">Wear</span>
          <span className="row-value">{battery.wear_percent.toFixed(1)}%</span>
        </div>
      )}
      {battery.cycle_count !== null && (
        <div className="row">
          <span className="row-label">Cycle Count</span>
          <span className="row-value">{battery.cycle_count}</span>
        </div>
      )}
      <div className="row">
        <span className="row-label">Design Capacity</span>
        <span className="row-value">
          {battery.design_capacity_mwh ? `${battery.design_capacity_mwh} mWh` : 'N/A'}
        </span>
      </div>
      <div className="row">
        <span className="row-label">Full Charge Capacity</span>
        <span className="row-value">
          {battery.full_charge_capacity_mwh ? `${battery.full_charge_capacity_mwh} mWh` : 'N/A'}
        </span>
      </div>
      <div className="row">
        <span className="row-label">Manufacturer</span>
        <span className="row-value">{battery.manufacturer || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">Name</span>
        <span className="row-value">{battery.battery_name || 'N/A'}</span>
      </div>
      <div className="row">
        <span className="row-label">Baseline</span>
        <span className="row-value">{battery.baseline_status}</span>
      </div>
    </div>
  )
}

function getStatusClass(status: string | null | undefined): string {
  switch (status?.toLowerCase()) {
    case 'charging':
    case 'full':
      return 'normal'
    case 'discharging':
      return 'warning'
    case 'critical':
    case 'empty':
      return 'critical'
    default:
      return 'muted'
  }
}
