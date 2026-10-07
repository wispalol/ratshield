import { Activity, Camera, Globe, Lock, Power, Radar } from 'lucide-react'

const features = [
  {
    icon: Radar,
    title: 'Process monitoring',
    description:
      'Continuously inspects running processes for unsigned binaries, injected code, and programs hiding in temp or AppData folders.',
  },
  {
    icon: Globe,
    title: 'Network watch',
    description:
      'Flags unexpected outbound connections, reverse shells, and traffic to known command-and-control servers.',
  },
  {
    icon: Power,
    title: 'Startup protection',
    description:
      'Audits registry Run keys, scheduled tasks, services, and startup folders where RATs hide to survive a reboot.',
  },
  {
    icon: Camera,
    title: 'Webcam & mic alerts',
    description:
      'Notifies you the moment an unknown app tries to access your camera, microphone, or capture your screen.',
  },
  {
    icon: Lock,
    title: 'One-click quarantine',
    description:
      'Kill the process, block its connection, and move the file into an isolated quarantine you can restore at any time.',
  },
  {
    icon: Activity,
    title: 'Lightweight',
    description:
      'Runs quietly in the system tray using minimal CPU and memory, so you stay protected without slowing down.',
  },
]

export function Features() {
  return (
    <section id="features" className="scroll-mt-20 border-t border-border py-24">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="max-w-2xl">
          <p className="font-mono text-sm text-primary">What it does</p>
          <h2 className="mt-3 text-balance text-3xl font-semibold tracking-tight sm:text-4xl">
            Everything a RAT needs to survive, RatShield watches.
          </h2>
          <p className="mt-4 text-pretty leading-relaxed text-muted-foreground">
            A Remote Access Trojan lets an attacker secretly control your computer &mdash; reading
            files, logging keystrokes, and watching through your webcam. RatShield covers every
            stage of how they get in and stay in.
          </p>
        </div>
        <ul className="mt-14 grid gap-px overflow-hidden rounded-2xl border border-border bg-border sm:grid-cols-2 lg:grid-cols-3">
          {features.map((feature) => (
            <li key={feature.title} className="bg-background p-8">
              <div className="flex size-10 items-center justify-center rounded-lg bg-accent text-primary">
                <feature.icon className="size-5" aria-hidden="true" />
              </div>
              <h3 className="mt-5 font-medium">{feature.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                {feature.description}
              </p>
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}
