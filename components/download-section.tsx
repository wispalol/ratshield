import { Check, Download, ShieldCheck } from 'lucide-react'
import { buttonVariants } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { download, releaseNotes } from '@/lib/site'

const requirements = [
  'Windows 10 or Windows 11 (64-bit)',
  '2 GB RAM or more',
  '100 MB free disk space',
  'Administrator rights for installation',
]

const installSteps = [
  `Download ${download.fileName} using the button.`,
  'Open the file. If SmartScreen appears, choose "More info" then "Run anyway".',
  'Follow the installer and launch RatShield.',
  'Click "Run Full Scan" to check your PC.',
]

export function DownloadSection() {
  return (
    <section id="download" className="scroll-mt-20 border-t border-border py-24">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="grid gap-8 overflow-hidden rounded-3xl border border-border bg-card p-8 md:p-12 lg:grid-cols-2 lg:gap-16">
          <div className="flex flex-col">
            <ShieldCheck className="size-10 text-primary" aria-hidden="true" />
            <h2 className="mt-6 text-balance text-3xl font-semibold tracking-tight sm:text-4xl">
              Download RatShield for Windows
            </h2>
            <p className="mt-4 text-pretty leading-relaxed text-muted-foreground">
              Get protected in under a minute. The installer is a single executable &mdash; no
              account or sign-up required.
            </p>
            <dl className="mt-8 grid grid-cols-2 gap-4 rounded-xl border border-border bg-background p-4 font-mono text-xs sm:grid-cols-4">
              <div>
                <dt className="text-muted-foreground">Released</dt>
                <dd className="mt-1 text-foreground">{download.released}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Version</dt>
                <dd className="mt-1 text-foreground">{download.version}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Size</dt>
                <dd className="mt-1 text-foreground">{download.size}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Format</dt>
                <dd className="mt-1 text-foreground">.exe</dd>
              </div>
            </dl>
            <a
              href={download.url}
              download={download.fileName}
              className={cn(buttonVariants({ size: 'lg' }), 'mt-8 h-12 self-start px-6 text-base')}
            >
              <Download aria-hidden="true" />
              {`Download ${download.fileName}`}
            </a>
          </div>

          <div className="grid gap-8">
            <div>
              <h3 className="font-medium">System requirements</h3>
              <ul className="mt-4 grid gap-3 text-sm text-muted-foreground">
                {requirements.map((item) => (
                  <li key={item} className="flex items-start gap-3">
                    <Check className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <h3 className="font-medium">Installation</h3>
              <ol className="mt-4 grid gap-3 text-sm text-muted-foreground">
                {installSteps.map((item, index) => (
                  <li key={item} className="flex items-start gap-3">
                    <span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-accent font-mono text-[11px] text-primary">
                      {index + 1}
                    </span>
                    {item}
                  </li>
                ))}
              </ol>
            </div>
            <div>
              <h3 className="font-medium">{`What's new in ${download.version}`}</h3>
              <ul className="mt-4 grid gap-2 text-sm text-muted-foreground">
                {releaseNotes.map((note) => (
                  <li key={note} className="flex items-start gap-3">
                    <span className="mt-2 size-1.5 shrink-0 rounded-full bg-primary" aria-hidden="true" />
                    {note}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
