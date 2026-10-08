import { Plus } from 'lucide-react'

const faqs = [
  {
    q: 'What is a RAT?',
    a: 'A Remote Access Trojan is malware that gives an attacker hidden, remote control of your computer. It is often disguised as a game mod, crack, or harmless attachment.',
  },
  {
    q: 'Does RatShield replace my antivirus?',
    a: 'No. RatShield is designed to work alongside Windows Defender or your existing antivirus, adding a focused layer of protection against remote access tools.',
  },
  {
    q: 'Why does Windows SmartScreen warn me?',
    a: 'SmartScreen shows a warning for newer apps that have not yet built up download reputation. Click "More info" and then "Run anyway" to continue.',
  },
  {
    q: 'Will it slow down my PC?',
    a: 'RatShield is lightweight and runs in the system tray. Real-time monitoring uses very little CPU and memory.',
  },
  {
    q: 'Can I restore something that was quarantined?',
    a: 'Yes. Quarantined files are kept in an isolated folder and can be restored or permanently deleted from the Quarantine tab.',
  },
  {
    q: 'What if it flags a program I trust?',
    a: 'Some legitimate tools, like remote desktop apps, behave similarly to RATs. You can mark any item as trusted and RatShield will stop alerting about it.',
  },
  {
    q: 'Does RatShield send my data anywhere?',
    a: 'No. All scanning happens locally on your PC, no account is needed, and quarantined files never leave your computer.',
  },
  {
    q: 'Why does it need administrator rights?',
    a: 'Admin rights let RatShield inspect every process, read system startup locations, and stop malware that runs with elevated permissions.',
  },
  {
    q: 'How do I uninstall it?',
    a: 'Open Windows Settings, go to Apps, find RatShield and choose Uninstall. Any quarantined files are removed along with it.',
  },
]

export function Faq() {
  return (
    <section id="faq" className="scroll-mt-20 border-t border-border py-24">
      <div className="mx-auto grid max-w-6xl gap-12 px-4 sm:px-6 lg:grid-cols-[1fr_2fr]">
        <div>
          <p className="font-mono text-sm text-primary">FAQ</p>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">Questions</h2>
          <p className="mt-4 text-pretty leading-relaxed text-muted-foreground">
            Everything you need to know before installing RatShield.
          </p>
        </div>
        <div className="divide-y divide-border border-y border-border">
          {faqs.map((item) => (
            <details key={item.q} className="group py-5">
              <summary className="flex cursor-pointer list-none items-center justify-between gap-4 font-medium [&::-webkit-details-marker]:hidden">
                {item.q}
                <Plus
                  className="size-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-45"
                  aria-hidden="true"
                />
              </summary>
              <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{item.a}</p>
            </details>
          ))}
        </div>
      </div>
    </section>
  )
}
