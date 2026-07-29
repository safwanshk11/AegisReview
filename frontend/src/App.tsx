import { FormEvent, useEffect, useMemo, useState } from 'react'

type Inspection = { repository_url: string; files: string[]; file_count: number; truncated: boolean }
type Analysis = { explanation: string; diff: string; review: string; approved: boolean }
type Finding = { file: string; line_number: number; rule: string; severity: 'low' | 'medium' | 'high' | 'critical'; analysis: Analysis | null }
type Activity = { finding_id: string; step: string; status: string; detail: string }
type Scan = { repository_url: string; scanned_files: number; findings: Finding[]; agent_activity: Activity[] }
type Mode = 'scan' | 'map'
type SortDirection = 'desc' | 'asc'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

const severityOrder: Finding['severity'][] = ['critical', 'high', 'medium', 'low']
const severityRank: Record<Finding['severity'], number> = { critical: 4, high: 3, medium: 2, low: 1 }
const healthPenalty: Record<Finding['severity'], number> = { critical: 25, high: 12, medium: 5, low: 2 }

function ShieldMark() {
  return <svg aria-hidden="true" className="shield-mark" viewBox="0 0 42 48" fill="none">
    <path d="M21 2 38 8v13c0 11.7-6.8 20.1-17 25C10.8 41.1 4 32.7 4 21V8L21 2Z" stroke="currentColor" strokeWidth="2.5" />
    <path d="m13 24 5.2 5.1L30 17" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
}

function DiffView({ diff }: { diff: string }) {
  return <pre className="diff"><code>{diff.split('\n').map((line, index) => {
    const kind = line.startsWith('+++') || line.startsWith('---') ? 'meta'
      : line.startsWith('@@') ? 'hunk'
      : line.startsWith('+') ? 'add'
      : line.startsWith('-') ? 'del' : 'ctx'
    return <span className={`diff-line ${kind}`} key={index}>{line || ' '}</span>
  })}</code></pre>
}

export default function App() {
  const [url, setUrl] = useState('')
  const [mode, setMode] = useState<Mode>('scan')
  const [inspection, setInspection] = useState<Inspection | null>(null)
  const [scan, setScan] = useState<Scan | null>(null)
  const [status, setStatus] = useState<'checking' | 'online' | 'offline'>('checking')
  const [message, setMessage] = useState('Ready when you are.')
  const [loading, setLoading] = useState(false)
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc')
  const [openRows, setOpenRows] = useState<Set<string>>(new Set())

  useEffect(() => {
    fetch(`${API_URL}/api/health`)
      .then((response) => response.ok ? response.json() : Promise.reject())
      .then(() => setStatus('online'))
      .catch(() => setStatus('offline'))
  }, [])

  const counts = useMemo(() => severityOrder.map((severity) => ({
    severity,
    count: scan?.findings.filter((finding) => finding.severity === severity).length ?? 0,
  })), [scan])

  const health = useMemo(() => Math.max(0, 100 - counts.reduce((total, { severity, count }) => total + count * healthPenalty[severity], 0)), [counts])
  const healthBand = health >= 80 ? { key: 'good', label: 'Healthy' } : health >= 50 ? { key: 'watch', label: 'Watch' } : { key: 'risk', label: 'At risk' }

  const sortedFindings = useMemo(() => [...(scan?.findings ?? [])].sort((a, b) => sortDirection === 'desc'
    ? severityRank[b.severity] - severityRank[a.severity]
    : severityRank[a.severity] - severityRank[b.severity]), [scan, sortDirection])

  function toggleRow(key: string) {
    setOpenRows((current) => {
      const next = new Set(current)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  async function run(event: FormEvent) {
    event.preventDefault()
    setLoading(true)
    setMessage(mode === 'scan' ? 'Scanning the repository…' : 'Mapping the repository…')
    setScan(null)
    setInspection(null)
    setOpenRows(new Set())

    try {
      if (mode === 'scan') await streamScan()
      else await inspect()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'The request did not complete.')
    } finally {
      setLoading(false)
    }
  }

  async function inspect() {
    const response = await fetch(`${API_URL}/api/repositories/inspect`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }),
    })
    const payload = await response.json()
    if (!response.ok) throw new Error(payload.detail ?? 'The repository could not be inspected.')
    setInspection(payload)
    setMessage('Repository map complete.')
  }

  async function streamScan() {
    const response = await fetch(`${API_URL}/api/repositories/scan/stream`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }),
    })
    if (!response.ok || !response.body) {
      const payload = await response.json().catch(() => ({}))
      throw new Error(payload.detail ?? 'The repository could not be scanned.')
    }
    const reader = response.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      const chunks = buffer.split('\n\n')
      buffer = chunks.pop() ?? ''
      for (const chunk of chunks) handleEvent(chunk)
    }
  }

  function handleEvent(chunk: string) {
    const name = chunk.match(/^event: (.*)$/m)?.[1]
    const data = chunk.match(/^data: (.*)$/m)?.[1]
    if (!name || !data) return
    const payload = JSON.parse(data)
    if (name === 'findings') {
      setScan({ repository_url: payload.repository_url, scanned_files: payload.scanned_files, findings: payload.findings, agent_activity: [] })
      setMessage(payload.findings.length ? 'Reviewing findings live…' : 'No signals found in this pass.')
    } else if (name === 'activity') {
      setScan((current) => current && { ...current, agent_activity: [...current.agent_activity, payload] })
    } else if (name === 'analysis') {
      setScan((current) => current && { ...current, findings: current.findings.map((finding, index) => index === payload.index ? { ...finding, analysis: payload.analysis } : finding) })
    } else if (name === 'done') {
      setMessage((current) => current === 'Reviewing findings live…' ? 'Review the signals below.' : current)
    } else if (name === 'error') {
      throw new Error(payload.detail)
    }
  }

  const hasResults = Boolean(scan || inspection)

  return <main className="app-shell">
    <div className="grain" />
    <header className="topbar">
      <a className="wordmark" href="/" aria-label="AegisReview home"><ShieldMark /><span>Aegis<span>Review</span></span></a>
      <div className={`system-status ${status}`}><i />{status === 'online' ? 'Engine connected' : status === 'offline' ? 'Engine offline' : 'Checking engine'}</div>
    </header>

    <section className="hero">
      <div className="eyebrow"><span />Security review, before the review</div>
      <div className="hero-grid">
        <div className="hero-copy">
          <h1>Make the first<br /><em>pass</em> count.</h1>
          <p>A focused first look for public GitHub repositories. Surface risky patterns, old dependencies, and the shape of the codebase before a human review begins.</p>
        </div>
        <div className="aegis-aperture" aria-hidden="true">
          <div className="aperture-rings" /><div className="aperture-core"><ShieldMark /></div>
          <span className="orbit orbit-a" /><span className="orbit orbit-b" />
          <small>ACTIVE DEFENCE<br />· 001 ·</small>
        </div>
      </div>
    </section>

    <section className="console" aria-label="Repository scan console">
      <div className="console-rail"><span>01</span><span>INPUT</span></div>
      <div className="console-body">
        <div className="mode-switch" role="tablist" aria-label="Review mode">
          <button className={mode === 'scan' ? 'active' : ''} onClick={() => setMode('scan')} role="tab" aria-selected={mode === 'scan'}>Security scan</button>
          <button className={mode === 'map' ? 'active' : ''} onClick={() => setMode('map')} role="tab" aria-selected={mode === 'map'}>File map</button>
        </div>
        <form onSubmit={run} className="repository-form">
          <label htmlFor="repository-url">GitHub repository</label>
          <div className="input-row">
            <span className="input-prefix">github.com/</span>
            <input id="repository-url" value={url} onChange={(event) => setUrl(event.target.value)} required placeholder="owner/repository" aria-describedby="form-hint" />
            <button disabled={loading}>{loading ? 'Working…' : mode === 'scan' ? 'Run scan' : 'Map files'} <span aria-hidden="true">↗</span></button>
          </div>
          <p id="form-hint">Public repositories only. Clones are created in a temporary workspace and discarded after each run.</p>
        </form>
      </div>
    </section>

    <section className={`report ${hasResults ? 'has-results' : ''}`} aria-live="polite">
      <div className="report-heading">
        <div><p className="eyebrow"><span />Current readout</p><h2>{hasResults ? message : 'A quiet screen is an invitation.'}</h2></div>
        {scan && <p className="scan-meta">{scan.scanned_files} files examined<br />{scan.findings.length} signals raised</p>}
      </div>

      {scan ? <div className="scan-report">
        <div className="summary-card">
          <div className={`health health-${healthBand.key}`}><b>{health}</b><span>repo health<br />{healthBand.label}</span></div>
          <div className="severity-strip">
            {counts.map(({ severity, count }) => <div className={`severity ${severity}`} key={severity}><b>{String(count).padStart(2, '0')}</b><span>{severity}</span></div>)}
          </div>
        </div>

        <div className="findings-panel">
          <div className="findings-head">
            <span>{sortedFindings.length} {sortedFindings.length === 1 ? 'finding' : 'findings'}</span>
            <button className="sort-toggle" onClick={() => setSortDirection((current) => current === 'desc' ? 'asc' : 'desc')} aria-label={`Sort by severity, ${sortDirection === 'desc' ? 'high to low' : 'low to high'}`}>Severity <span aria-hidden="true">{sortDirection === 'desc' ? '↓' : '↑'}</span></button>
          </div>
          <div className="findings">
            {sortedFindings.length ? sortedFindings.map((finding) => {
              const key = `${finding.file}:${finding.line_number}:${finding.rule}`
              const open = openRows.has(key)
              return <div className={`finding-row ${open ? 'open' : ''}`} key={key}>
                <button className="finding" onClick={() => toggleRow(key)} aria-expanded={open}>
                  <span className={`severity-dot ${finding.severity}`} />
                  <div><h3>{finding.rule}</h3><p>{finding.file}<span>line {finding.line_number}</span></p></div>
                  <span className={`severity-label ${finding.severity}`}>{finding.severity}</span>
                  <span className="finding-chevron" aria-hidden="true">{open ? '–' : '+'}</span>
                </button>
                {open && <div className="finding-detail">
                  {finding.analysis ? <>
                    <div className="detail-block"><h4>Explanation</h4><p>{finding.analysis.explanation}</p></div>
                    <div className="detail-block"><h4>Suggested fix<span className={`verdict ${finding.analysis.approved ? 'ok' : 'flag'}`}>{finding.analysis.approved ? 'self-review passed' : 'needs attention'}</span></h4><DiffView diff={finding.analysis.diff} /></div>
                    <div className="detail-block"><h4>Agent review</h4><p>{finding.analysis.review}</p></div>
                  </> : <p className="detail-empty">Agent analysis unavailable. Set OPENAI_API_KEY to enable the plan → act → review loop.</p>}
                </div>}
              </div>
            }) : <div className="clear-state"><ShieldMark /><p>No matching risk patterns were found.</p><small>That is a clean first pass—not a guarantee of safety.</small></div>}
          </div>
        </div>

        {scan.agent_activity.length > 0 && <div className="agent-log">
          <div className="agent-log-head"><span className="agent-log-title"><i />Agent activity log</span><span className="agent-log-count">{scan.agent_activity.length} {scan.agent_activity.length === 1 ? 'step' : 'steps'}{loading ? ' · streaming' : ''}</span></div>
          <ol className="agent-steps">
            {scan.agent_activity.map((entry, index) => <li className={`agent-step step-${entry.step} status-${entry.status}`} key={`${entry.finding_id}-${entry.step}-${index}`}>
              <span className="step-tag">{entry.step}</span>
              <div><p className="step-target">{entry.finding_id}</p><p className="step-detail">{entry.detail}</p></div>
              <span className={`step-status status-${entry.status}`}>{entry.status}</span>
            </li>)}
            {loading && <li className="agent-step pending"><span className="step-tag">···</span><div><p className="step-detail">Streaming agent steps…</p></div></li>}
          </ol>
        </div>}
      </div> : inspection ? <div className="map-report">
        <div className="map-total"><b>{inspection.file_count}{inspection.truncated ? '+' : ''}</b><span>files mapped</span></div>
        <ul>{inspection.files.map((file) => <li key={file}>{file}</li>)}</ul>
      </div> : <div className="empty-state"><div className="empty-glyph">↙</div><p>Point Aegis at a repository to begin.</p><small>Choose a security scan for risk signals, or a file map for orientation.</small></div>}
    </section>

    <footer><span>AegisReview · local static analysis</span><span>Public repository workflow</span></footer>
  </main>
}
