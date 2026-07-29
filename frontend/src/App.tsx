import { FormEvent, useEffect, useMemo, useState } from 'react'

type Inspection = { repository_url: string; files: string[]; file_count: number; truncated: boolean }
type Finding = { file: string; line_number: number; rule: string; severity: 'low' | 'medium' | 'high' | 'critical' }
type Scan = { repository_url: string; scanned_files: number; findings: Finding[] }
type Mode = 'scan' | 'map'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

const severityOrder: Finding['severity'][] = ['critical', 'high', 'medium', 'low']

function ShieldMark() {
  return <svg aria-hidden="true" className="shield-mark" viewBox="0 0 42 48" fill="none">
    <path d="M21 2 38 8v13c0 11.7-6.8 20.1-17 25C10.8 41.1 4 32.7 4 21V8L21 2Z" stroke="currentColor" strokeWidth="2.5" />
    <path d="m13 24 5.2 5.1L30 17" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
}

export default function App() {
  const [url, setUrl] = useState('')
  const [mode, setMode] = useState<Mode>('scan')
  const [inspection, setInspection] = useState<Inspection | null>(null)
  const [scan, setScan] = useState<Scan | null>(null)
  const [status, setStatus] = useState<'checking' | 'online' | 'offline'>('checking')
  const [message, setMessage] = useState('Ready when you are.')
  const [loading, setLoading] = useState(false)

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

  async function run(event: FormEvent) {
    event.preventDefault()
    setLoading(true)
    setMessage(mode === 'scan' ? 'Scanning the repository…' : 'Mapping the repository…')
    setScan(null)
    setInspection(null)

    try {
      const endpoint = mode === 'scan' ? 'scan' : 'inspect'
      const response = await fetch(`${API_URL}/api/repositories/${endpoint}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }),
      })
      const payload = await response.json()
      if (!response.ok) throw new Error(payload.detail ?? 'The repository could not be inspected.')
      if (mode === 'scan') {
        setScan(payload)
        setMessage(payload.findings.length ? 'Review the signals below.' : 'No signals found in this pass.')
      } else {
        setInspection(payload)
        setMessage('Repository map complete.')
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'The request did not complete.')
    } finally {
      setLoading(false)
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
        <div className="severity-strip">
          {counts.map(({ severity, count }) => <div className={`severity ${severity}`} key={severity}><b>{String(count).padStart(2, '0')}</b><span>{severity}</span></div>)}
        </div>
        <div className="findings">
          {scan.findings.length ? scan.findings.map((finding, index) => <article className="finding" key={`${finding.file}-${finding.line_number}-${index}`}>
            <span className={`severity-dot ${finding.severity}`} />
            <div><h3>{finding.rule}</h3><p>{finding.file}<span>line {finding.line_number}</span></p></div>
            <span className={`severity-label ${finding.severity}`}>{finding.severity}</span>
          </article>) : <div className="clear-state"><ShieldMark /><p>No matching risk patterns were found.</p><small>That is a clean first pass—not a guarantee of safety.</small></div>}
        </div>
      </div> : inspection ? <div className="map-report">
        <div className="map-total"><b>{inspection.file_count}{inspection.truncated ? '+' : ''}</b><span>files mapped</span></div>
        <ul>{inspection.files.map((file) => <li key={file}>{file}</li>)}</ul>
      </div> : <div className="empty-state"><div className="empty-glyph">↙</div><p>Point Aegis at a repository to begin.</p><small>Choose a security scan for risk signals, or a file map for orientation.</small></div>}
    </section>

    <footer><span>AegisReview · local static analysis</span><span>Public repository workflow</span></footer>
  </main>
}
