import Image from 'next/image'
import { ArrowRight, Download } from 'lucide-react'
import { buttonVariants } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { download } from '@/lib/site'

export function Hero() {
  return (
    <section className="relative overflow-hidden">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-x-0 top-0 h-[480px] bg-[radial-gradient(ellipse_at_top,oklch(0.76_0.17_158/0.18),transparent_65%)]"
      />
      <div className="relative mx-auto max-w-6xl px-4 pt-20 pb-16 sm:px-6 md:pt-28">
        <div className="mx-auto max-w-3xl text-center">
          <p className="mb-6 inline-flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1 font-mono text-xs text-muted-foreground">
            <span className="size-1.5 rounded-full bg-primary" aria-hidden="true" />
            {`v${download.version} for Windows`}
          </p>
          <h1 className="text-balance text-4xl font-semibold tracking-tight sm:text-5xl md:text-6xl">
            Stop remote access trojans before they take control.
          </h1>
          <p className="mx-auto mt-6 max-w-2xl text-pretty text-lg leading-relaxed text-muted-foreground">
            RatShield watches your Windows PC for the tell-tale signs of a RAT &mdash; hidden processes,
            suspicious outbound connections, and sneaky startup entries &mdash; and shuts them down
            before anyone can spy on you.
          </p>
          <div className="mt-10 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <a
              href={download.url}
              download={download.fileName}
              className={cn(buttonVariants({ size: 'lg' }), 'h-12 px-6 text-base')}
            >
              <Download aria-hidden="true" />
              Download for Windows
            </a>
            <a
              href="#how-it-works"
              className={cn(buttonVariants({ variant: 'outline', size: 'lg' }), 'h-12 px-6 text-base')}
            >
              See how it works
              <ArrowRight aria-hidden="true" />
            </a>
          </div>
          <p className="mt-4 font-mono text-xs text-muted-foreground">
            {`${download.fileName} · ${download.size} · ${download.platform}`}
          </p>
        </div>

        <div className="mx-auto mt-16 max-w-5xl rounded-2xl border border-border bg-card p-2 shadow-2xl shadow-primary/5">
          <Image
            src="/images/ratshield-app.png"
            alt="RatShield dashboard showing system protected status, real-time network connections and a process monitor"
            width={1312}
            height={816}
            priority
            className="h-auto w-full rounded-xl"
          />
        </div>
      </div>
    </section>
  )
}
