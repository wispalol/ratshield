import { SectionHeading } from '@/components/section-heading'

const checks = [
  {
    area: 'Processes',
    what: 'Executables running from Temp, AppData or Downloads, unsigned binaries, code injected into other processes.',
  },
  {
    area: 'Network',
    what: 'Connections to unknown IPs on unusual ports, reverse shells, and traffic to known command-and-control servers.',
  },
  {
    area: 'Persistence',
    what: 'HKCU and HKLM Run keys, Startup folders, scheduled tasks, new services and WMI subscriptions.',
  },
  {
    area: 'Spying',
    what: 'Apps opening the webcam or microphone, global keyboard hooks, and repeated screen captures.',
  },
  {
    area: 'Tampering',
    what: 'Attempts to disable Windows Defender, edit the hosts file, or add firewall exceptions.',
  },
]

const privacy = [
  'Scans happen locally on your PC',
  'No account or sign-in',
  'Quarantined files never leave your computer',
  'Works offline',
]

export function UnderTheHood() {
  return (
    <section id="technical" className="scroll-mt-20 border-t border-border py-24">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <SectionHeading
          eyebrow="Under the hood"
          title="Exactly what RatShield checks."
          description="No black box. Here is what each detection area looks for on your system."
        />

        <div className="mt-14 grid gap-12 lg:grid-cols-[2fr_1fr]">
          <dl className="divide-y divide-border rounded-2xl border border-border">
            {checks.map((check) => (
              <div key={check.area} className="grid gap-2 p-6 sm:grid-cols-[140px_1fr] sm:gap-6">
                <dt className="font-mono text-sm text-primary">{check.area}</dt>
                <dd className="text-sm leading-relaxed text-muted-foreground">{check.what}</dd>
              </div>
            ))}
          </dl>

          <div className="rounded-2xl border border-border bg-card p-6">
            <h3 className="font-medium">Private by design</h3>
            <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
              RatShield is built to protect your privacy, not collect it.
            </p>
            <ul className="mt-5 grid gap-3 text-sm">
              {privacy.map((item) => (
                <li key={item} className="flex items-start gap-3">
                  <span className="mt-2 size-1.5 shrink-0 rounded-full bg-primary" aria-hidden="true" />
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </section>
  )
}
