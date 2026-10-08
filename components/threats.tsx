import { SectionHeading } from '@/components/section-heading'

const threats = [
  {
    title: 'Keylogging',
    description: 'Recording everything you type, including passwords and messages.',
  },
  {
    title: 'Screen & webcam spying',
    description: 'Silently capturing your screen, camera or microphone.',
  },
  {
    title: 'File theft',
    description: 'Copying documents, saved browser logins and Discord or game tokens.',
  },
  {
    title: 'Remote control',
    description: 'Running commands, moving your mouse or installing more malware.',
  },
]

const signs = [
  'Webcam light turns on by itself',
  'Unknown processes using the network',
  'PC is slow or fans spin while idle',
  'Accounts logged in from places you don\u2019t recognise',
  'New programs appearing at startup',
  'Antivirus suddenly disabled',
]

export function Threats() {
  return (
    <section id="threats" className="scroll-mt-20 border-t border-border py-24">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <SectionHeading
          eyebrow="The problem"
          title="What a RAT can do to your PC."
          description="A Remote Access Trojan is malware that gives someone else hidden control of your computer. They usually arrive disguised as a cheat, crack, game mod, or a file sent over Discord."
        />

        <div className="mt-14 grid gap-12 lg:grid-cols-[3fr_2fr]">
          <ul className="grid gap-4 sm:grid-cols-2">
            {threats.map((threat) => (
              <li key={threat.title} className="rounded-2xl border border-border bg-card p-6">
                <h3 className="font-medium">{threat.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                  {threat.description}
                </p>
              </li>
            ))}
          </ul>

          <div className="rounded-2xl border border-border p-6">
            <h3 className="font-medium">Warning signs you may be infected</h3>
            <ul className="mt-5 grid gap-3 text-sm text-muted-foreground">
              {signs.map((sign) => (
                <li key={sign} className="flex items-start gap-3">
                  <span className="mt-2 size-1.5 shrink-0 rounded-full bg-destructive" aria-hidden="true" />
                  {sign}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </section>
  )
}
