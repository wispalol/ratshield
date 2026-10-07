const steps = [
  {
    title: 'Scan',
    description:
      'On launch, RatShield performs a full sweep of running processes, loaded modules, startup locations, and open network ports.',
    detail: 'processes · services · registry · ports',
  },
  {
    title: 'Analyze',
    description:
      'Each item is scored using signature matching against known RAT families plus behavioral heuristics — like a hidden window that opens a socket and logs keys.',
    detail: 'signatures + behavior heuristics',
  },
  {
    title: 'Monitor',
    description:
      'After the first scan, RatShield keeps watching in real time. New processes, new connections, and new startup entries are checked the moment they appear.',
    detail: 'real-time, low overhead',
  },
  {
    title: 'Respond',
    description:
      'When a threat is found, you get an alert with the details. Terminate it, block its network access, and quarantine the file in one click.',
    detail: 'kill · block · quarantine',
  },
]

export function HowItWorks() {
  return (
    <section id="how-it-works" className="scroll-mt-20 border-t border-border bg-card/40 py-24">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="max-w-2xl">
          <p className="font-mono text-sm text-primary">How it works</p>
          <h2 className="mt-3 text-balance text-3xl font-semibold tracking-tight sm:text-4xl">
            Four layers between you and an attacker.
          </h2>
        </div>
        <ol className="mt-14 grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {steps.map((step, index) => (
            <li key={step.title} className="flex flex-col rounded-2xl border border-border bg-background p-6">
              <span className="font-mono text-sm text-muted-foreground">
                {String(index + 1).padStart(2, '0')}
              </span>
              <h3 className="mt-4 text-lg font-medium">{step.title}</h3>
              <p className="mt-2 flex-1 text-sm leading-relaxed text-muted-foreground">
                {step.description}
              </p>
              <p className="mt-6 border-t border-border pt-4 font-mono text-xs text-primary">
                {step.detail}
              </p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  )
}
