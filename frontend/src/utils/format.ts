// Formatting utilities for the dashboard

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return 'N/A'
  if (bytes === 0) return '0 B'

  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const k = 1024
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  const value = bytes / Math.pow(k, i)

  return `${value.toFixed(1)} ${units[i]}`
}

export function formatPercent(percent: number | null): string {
  if (percent === null || percent === undefined) return 'N/A'
  return `${percent.toFixed(1)}%`
}

export function getStatusColor(status: string): string {
  switch (status?.toLowerCase()) {
    case 'normal':
    case 'ok':
    case 'completed':
    case 'available':
      return 'var(--color-normal)'
    case 'warning':
      return 'var(--color-warning)'
    case 'critical':
    case 'error':
    case 'failed':
      return 'var(--color-critical)'
    case 'not_available':
    case 'not analyzed':
    case 'not run':
      return 'var(--color-muted)'
    default:
      return 'var(--color-text)'
  }
}

export function getSeverityColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'var(--color-critical)'
    case 'warning':
      return 'var(--color-warning)'
    case 'info':
      return 'var(--color-info)'
    default:
      return 'var(--color-text)'
  }
}

export function getRiskColor(risk: string): string {
  switch (risk?.toLowerCase()) {
    case 'low':
      return 'var(--color-normal)'
    case 'medium':
      return 'var(--color-warning)'
    case 'high':
    case 'critical':
      return 'var(--color-critical)'
    default:
      return 'var(--color-text)'
  }
}
