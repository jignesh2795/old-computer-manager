import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import App from './App'

vi.mock('./api/client', () => ({
  api: {
    health: vi.fn(),
    report: vi.fn(),
    findings: vi.fn(),
    storage: vi.fn(),
    battery: vi.fn(),
    fileAnalysis: vi.fn(),
    remediationActions: vi.fn(),
    system: vi.fn(),
    advisory: vi.fn(),
    history: vi.fn(),
    diagnosticsSummary: vi.fn(),
    diagnosticsDisk: vi.fn(),
    diagnosticsThermal: vi.fn(),
    diagnosticsPerformance: vi.fn(),
    diagnosticsDevices: vi.fn(),
    diagnosticsWindows: vi.fn(),
  },
}))

import { api } from './api/client'

const mockReport = {
  schema_version: '1.0',
  generated_at: '2026-09-16T12:00:00',
  discovery_run_id: 1,
  discovery_status: 'completed',
  analysis_status: 'completed',
  findings_available: true,
  findings_count: 3,
  system: {
    hostname: 'TEST-PC',
    os_name: 'Windows 10',
    os_version: '10.0.19045',
    architecture: '64-bit',
    manufacturer: 'Test',
    model: 'Test Model',
    bios_vendor: 'Test BIOS',
    bios_version: '1.0',
    cpu_name: 'Test CPU',
    cpu_cores_physical: 2,
    cpu_cores_logical: 4,
    ram_total_bytes: 8589934592,
  },
  storage: {
    partitions: [
      {
        device: 'C:',
        filesystem: 'NTFS',
        total_bytes: 250000000000,
        used_bytes: 200000000000,
        free_bytes: 50000000000,
        usage_percent: 80,
        status: 'warning',
      },
    ],
    count: 1,
    total_capacity_bytes: 250000000000,
    total_free_bytes: 50000000000,
  },
  battery: {
    available: true,
    status: 'charging',
    charge_percent: 75,
    plugged_in: true,
    design_capacity_mwh: 40000,
    full_charge_capacity_mwh: 35000,
    remaining_capacity_mwh: 26250,
    health_percent: 87.5,
    wear_percent: 12.5,
    health_status: 'good',
    cycle_count: 100,
    manufacturer: 'Test',
    battery_name: 'Test Battery',
    baseline_status: 'non-baseline',
  },
  findings: {
    analysis_status: 'completed',
    findings_available: true,
    findings_count: 3,
    critical_count: 0,
    warning_count: 3,
    info_count: 0,
    findings: [
      {
        finding_id: '1',
        analyzer: 'storage',
        severity: 'warning',
        title: 'Disk usage high',
        message: 'C: is 80% full',
        evidence: { percent_used: 80 },
        recommendation: 'Free up space',
        created_at: '2026-09-16T12:00:00',
      },
    ],
  },
  software: {},
  startup: {},
  processes: {},
  services: {},
  scheduled_tasks: {},
  file_analysis: {
    available: true,
    scan_root: '/test',
    scan_timestamp: '2026-09-16T12:00:00',
    files_examined: 100,
    directories_examined: 10,
    bytes_examined: 1000000,
    files_skipped: 5,
    symlinks_skipped: 2,
    excluded_items: 3,
    inaccessible_items: 1,
    largest_files: [{ path: '/test/large.bin', size: 500000 }],
    largest_directories: [{ path: '/test', size: 1000000 }],
    file_type_summary: [],
    duplicate_groups: 2,
    potential_duplicate_bytes: 100000,
  },
  remediation: {
    actions: [
      {
        action_id: 'user_temp_quarantine',
        name: 'Quarantine old temporary files',
        risk_level: 'medium',
        reversible: true,
        requires_admin: false,
        preview_available: true,
        rollback_available: true,
        real_execution_exists: true,
      },
    ],
    count: 1,
  },
  diagnostics: {
    available: false,
    run_id: null,
    status: null,
    result_count: 0,
    categories: [],
    status_counts: {},
    results: [],
  },
  errors: [],
}

const mockAdvisory = {
  schema_version: '1.0',
  generated_at: '2026-09-16T12:00:00',
  report_run_id: 1,
  analysis_status: 'completed',
  summary: 'Test advisory summary',
  observations: [
    {
      title: 'Test observation',
      evidence: 'Test evidence',
      source: 'test_analyzer',
      severity: 'warning',
      confidence: 'high',
    },
  ],
  recommendations: [
    {
      title: 'Test recommendation',
      rationale: 'Test rationale',
      related_finding_ids: ['1'],
      related_action_ids: ['user_temp_quarantine'],
      risk_level: 'low',
      requires_confirmation: true,
      executable: false,
    },
  ],
  uncertainties: [
    {
      description: 'Test uncertainty',
      impact: 'Test impact',
    },
  ],
  limitations: [
    {
      description: 'Test limitation',
    },
  ],
  metadata: {
    provider: 'mock',
    model: 'deterministic',
    prompt_version: '1.1',
    generated_at: '2026-09-16T12:00:00',
  },
  historical_summary: {
    runs_considered: 5,
    observations_used: 3,
    trends_count: 2,
    baselines_established: 1,
    recurring_findings_count: 1,
    anomalies_count: 0,
    data_quality_issues: 0,
    limited_by: '',
  },
}

function setupMocks() {
  vi.mocked(api.report).mockResolvedValue(mockReport as any)
  vi.mocked(api.advisory).mockResolvedValue(mockAdvisory as any)
  vi.mocked(api.findings).mockResolvedValue(mockReport.findings as any)
  vi.mocked(api.storage).mockResolvedValue(mockReport.storage as any)
  vi.mocked(api.battery).mockResolvedValue(mockReport.battery as any)
  vi.mocked(api.fileAnalysis).mockResolvedValue(mockReport.file_analysis as any)
  vi.mocked(api.remediationActions).mockResolvedValue(mockReport.remediation as any)
  vi.mocked(api.system).mockResolvedValue(mockReport.system as any)
  vi.mocked(api.history).mockResolvedValue(null as any)
  vi.mocked(api.diagnosticsSummary).mockResolvedValue(mockReport.diagnostics as any)
}

async function clickRefresh() {
  const user = userEvent.setup()
  await user.click(screen.getByText('Refresh'))
}

describe('Dashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders dashboard header with refresh button', () => {
    render(<App />)
    expect(screen.getByText('Old Computer Manager')).toBeInTheDocument()
    expect(screen.getByText('Refresh')).toBeInTheDocument()
  })

  it('shows empty state before refresh', () => {
    render(<App />)
    expect(screen.getByText('Click Refresh to load dashboard data')).toBeInTheDocument()
  })

  it('renders overview after data load', async () => {
    setupMocks()
    render(<App />)
    await clickRefresh()

    await waitFor(() => {
      expect(screen.getAllByText('TEST-PC').length).toBeGreaterThan(0)
    })
    expect(screen.getByText('Windows 10 10.0.19045')).toBeInTheDocument()
    expect(screen.getAllByText('Test Model').length).toBeGreaterThan(0)
  })

  it('renders findings with correct status', async () => {
    setupMocks()
    render(<App />)
    await clickRefresh()

    await waitFor(() => {
      expect(screen.getByText('Disk usage high')).toBeInTheDocument()
    })
    expect(screen.getAllByText('warning').length).toBeGreaterThan(0)
  })

  it('shows not analyzed when analysis not run', async () => {
    const reportWithNoAnalysis = {
      ...mockReport,
      analysis_status: 'not_run',
      findings_available: false,
      findings_count: null,
      findings: {
        analysis_status: 'not_run',
        findings_available: false,
        findings_count: null,
        critical_count: 0,
        warning_count: 0,
        info_count: 0,
        findings: [],
      },
    }
    vi.mocked(api.report).mockResolvedValue(reportWithNoAnalysis as any)
    vi.mocked(api.advisory).mockResolvedValue(null)
    vi.mocked(api.findings).mockResolvedValue(reportWithNoAnalysis.findings as any)
    vi.mocked(api.storage).mockResolvedValue(mockReport.storage as any)
    vi.mocked(api.battery).mockResolvedValue(mockReport.battery as any)
    vi.mocked(api.fileAnalysis).mockResolvedValue(mockReport.file_analysis as any)
    vi.mocked(api.remediationActions).mockResolvedValue(mockReport.remediation as any)
    vi.mocked(api.system).mockResolvedValue(mockReport.system as any)
    vi.mocked(api.history).mockResolvedValue(null as any)
    vi.mocked(api.diagnosticsSummary).mockResolvedValue(mockReport.diagnostics as any)

    render(<App />)
    await clickRefresh()

    await waitFor(() => {
      expect(screen.getByText('Analysis not run')).toBeInTheDocument()
    })
  })

  it('renders battery unavailable state', async () => {
    vi.mocked(api.report).mockResolvedValue(mockReport as any)
    vi.mocked(api.advisory).mockResolvedValue(mockAdvisory as any)
    vi.mocked(api.findings).mockResolvedValue(mockReport.findings as any)
    vi.mocked(api.storage).mockResolvedValue(mockReport.storage as any)
    vi.mocked(api.battery).mockResolvedValue({
      available: false,
      status: null,
      charge_percent: null,
      plugged_in: null,
      design_capacity_mwh: null,
      full_charge_capacity_mwh: null,
      remaining_capacity_mwh: null,
      health_percent: null,
      wear_percent: null,
      health_status: null,
      cycle_count: null,
      manufacturer: null,
      battery_name: null,
      baseline_status: 'non-baseline',
    } as any)
    vi.mocked(api.fileAnalysis).mockResolvedValue(mockReport.file_analysis as any)
    vi.mocked(api.remediationActions).mockResolvedValue(mockReport.remediation as any)
    vi.mocked(api.system).mockResolvedValue(mockReport.system as any)
    vi.mocked(api.history).mockResolvedValue(null as any)
    vi.mocked(api.diagnosticsSummary).mockResolvedValue(mockReport.diagnostics as any)

    render(<App />)
    await clickRefresh()

    await waitFor(() => {
      expect(screen.getAllByText('Not available').length).toBeGreaterThan(0)
    })
  })

  it('renders storage data', async () => {
    setupMocks()
    render(<App />)
    await clickRefresh()

    await waitFor(() => {
      expect(screen.getByText('C:')).toBeInTheDocument()
    })
    expect(screen.getByText('NTFS')).toBeInTheDocument()
    expect(screen.getByText('80.0%')).toBeInTheDocument()
  })

  it('renders AI advisory', async () => {
    setupMocks()
    render(<App />)
    await clickRefresh()

    await waitFor(() => {
      expect(screen.getByText('Test observation')).toBeInTheDocument()
    })
    expect(screen.getByText('Test recommendation')).toBeInTheDocument()
    expect(screen.getByText('mock')).toBeInTheDocument()
  })

  it('renders remediation metadata', async () => {
    setupMocks()
    render(<App />)
    await clickRefresh()

    await waitFor(() => {
      expect(screen.getByText('Quarantine old temporary files')).toBeInTheDocument()
    })
    expect(screen.getByText('user_temp_quarantine')).toBeInTheDocument()
    expect(screen.getByText('medium')).toBeInTheDocument()
  })

  it('has no execution buttons', async () => {
    setupMocks()
    render(<App />)
    await clickRefresh()

    await waitFor(() => {
      expect(screen.getByText('Refresh')).toBeInTheDocument()
    })

    const buttons = screen.getAllByRole('button')
    const buttonTexts = buttons.map((btn) => btn.textContent?.toLowerCase() || '')
    expect(buttonTexts.some((text) => text.includes('apply'))).toBe(false)
    expect(buttonTexts.some((text) => text.includes('execute'))).toBe(false)
    expect(buttonTexts.some((text) => text.includes('delete'))).toBe(false)
    expect(buttonTexts.some((text) => text.includes('cleanup'))).toBe(false)
  })

  it('handles API failure gracefully', async () => {
    vi.mocked(api.report).mockRejectedValue(new Error('API unavailable'))
    vi.mocked(api.advisory).mockResolvedValue(null)
    vi.mocked(api.findings).mockResolvedValue(null)
    vi.mocked(api.storage).mockResolvedValue(null)
    vi.mocked(api.battery).mockResolvedValue(null)
    vi.mocked(api.fileAnalysis).mockResolvedValue(null)
    vi.mocked(api.remediationActions).mockResolvedValue(null)
    vi.mocked(api.system).mockResolvedValue(null)
    vi.mocked(api.history).mockResolvedValue(null)
    vi.mocked(api.diagnosticsSummary).mockResolvedValue(null)

    render(<App />)
    await clickRefresh()

    await waitFor(() => {
      expect(api.report).toHaveBeenCalled()
    })

    expect(screen.getByText('Click Refresh to load dashboard data')).toBeInTheDocument()
  })

  it('no automatic discovery/analyze call occurs on mount', async () => {
    setupMocks()
    render(<App />)

    await new Promise((resolve) => setTimeout(resolve, 100))

    expect(api.report).not.toHaveBeenCalled()
    expect(api.system).not.toHaveBeenCalled()
  })

  it('manual refresh calls API endpoints', async () => {
    setupMocks()
    render(<App />)
    await clickRefresh()

    await waitFor(() => {
      expect(api.report).toHaveBeenCalled()
      expect(api.system).toHaveBeenCalled()
    })
  })
})
