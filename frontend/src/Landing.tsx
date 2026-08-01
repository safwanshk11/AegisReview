import { ShieldMark } from './App'

const features = [
  { title: 'Static security scan', body: 'Dependency-free checks for hardcoded secrets, SQL built with string interpolation, unsafe HTML rendering, eval/exec usage, and known-vulnerable dependencies. Runs instantly, free, no account needed.' },
  { title: 'Agentic AI review', body: 'Turn it on when you want more: an agent plans, drafts, and self-checks a fix for your most severe findings — plain-English explanation, a suggested diff, and its own review of that diff.' },
  { title: 'Nothing is stored', body: 'Repositories are downloaded to a temporary workspace for the scan and discarded immediately after. Secrets are redacted before anything is ever sent to the AI model.' },
]

const steps = [
  { title: 'Paste a repository', body: 'Drop in any public GitHub repository — just owner/repository, or the full URL.' },
  { title: 'Run the scan', body: 'The static scan runs immediately: hardcoded secrets, risky patterns, and outdated dependencies, sorted by severity.' },
  { title: 'Turn on AI review — optional', body: 'Flip the switch to have the agent explain and propose a fix for your most severe findings, live.' },
  { title: 'Review, sort, export', body: 'Expand any finding for the full detail, sort by severity, or export the whole report as Markdown or JSON.' },
]

export default function Landing({ onStart }: { onStart: () => void }) {
  return <main className="app-shell landing">
    <div className="grain" />
    <header className="topbar">
      <span className="wordmark"><ShieldMark /><span>Aegis<span>Review</span></span></span>
      <button className="topbar-start" onClick={onStart}>Start <span aria-hidden="true">↗</span></button>
    </header>

    <section className="hero">
      <div className="eyebrow"><span />Security review, before the review</div>
      <div className="hero-grid">
        <div className="hero-copy">
          <h1>Know what's <em>risky</em><br />before anyone else does.</h1>
          <p>AegisReview gives any public GitHub repository a fast, automated first-pass security review — the kind a human reviewer does first, done in seconds, for free.</p>
        </div>
        <div className="aegis-aperture" aria-hidden="true">
          <div className="aperture-rings" /><div className="aperture-core"><ShieldMark /></div>
          <span className="orbit orbit-a" /><span className="orbit orbit-b" />
          <small>ACTIVE DEFENCE<br />· 001 ·</small>
        </div>
      </div>
    </section>

    <section className="landing-about">
      <p className="eyebrow"><span />What it does</p>
      <div className="feature-grid">
        {features.map((feature) => <div className="feature-card" key={feature.title}>
          <h3>{feature.title}</h3>
          <p>{feature.body}</p>
        </div>)}
      </div>
    </section>

    <section className="landing-how">
      <p className="eyebrow"><span />How to use it</p>
      <ol className="how-steps">
        {steps.map((step, index) => <li key={step.title}>
          <span className="how-index">{String(index + 1).padStart(2, '0')}</span>
          <div><h3>{step.title}</h3><p>{step.body}</p></div>
        </li>)}
      </ol>
    </section>

    <section className="landing-cta">
      <h2>Point it at a repository.<br />See what it finds.</h2>
      <button className="cta-button" onClick={onStart}>Let's go <span aria-hidden="true">→</span></button>
      <p>Public repositories only — your code is never stored.</p>
    </section>

    <footer><span>AegisReview · local static analysis</span><span>Public repository workflow</span></footer>
  </main>
}
