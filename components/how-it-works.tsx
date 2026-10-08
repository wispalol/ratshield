import { SectionHeading } from '@/components/section-heading'

const steps = [
  {
    title: 'Scan',
    description:
      'On launch, RatShield sweeps your whole system to build a picture of what is running and what starts with Windows.',
    points: ['Running processes & loaded DLLs', 'Services & scheduled tasks', 'Registry Run keys', 'Open ports'],
  },
  {
    title: 'Analyze',
    description:
      'Every item is scored using signatures of known RAT families plus behaviour checks for things legitimate apps rarely do.',
    points: ['Known RAT signatures', 'Unsigned or packed files', 'Hidden windows with sockets', 'Keyboard hooks'],
  },
  {
    title: 'Monitor',
    description:
      'After the first scan, RatShield keeps watching in real time and checks new activity the moment it appears.',
    points: ['New processes', 'New outbound connections', 'New startup entries', 'Camera & mic access'],
  },
  {
    title: 'Respond',
    description:
      'When something is flagged, you get a clear alert explaining why, and you decide what happens next.',
    points: ['Terminate the process', 'Block its connection', 'Quarantine the file', 'Or mark it as trusted'],
  },
]

export function HowItWorks() {
  return (
    <section id="how-it-works" className="scroll-mt-20 border-t border-border bg-card/40 py-24">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <SectionHeading
          eyebrow="How it works"
          title="Four layers between you and an attacker."
          description="RatShield runs these four steps continuously, so threats are caught whether they were already on your PC or arrive later."
        />
        <ol className="mt-14 grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {steps.map((step, index) => (
            <li key={step.title} className="flex flex-col rounded-2xl border border-border bg-background p-6">
              <span className="font-mono text-sm text-muted-foreground">
                {String(index + 1).padStart(2, '0')}
              </span>
              <h3 className="mt-4 text-lg font-medium">{step.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{step.description}</p>
              <ul className="mt-6 grid gap-2 border-t border-border pt-4 font-mono text-xs text-primary">
                {step.points.map((point) => (
                  <li key={point}>{point}</li>
                ))}
              </ul>
            </li>
          ))}
        </ol>
      </div>
    </section>
  )
}
