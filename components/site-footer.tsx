import { ShieldCheck } from 'lucide-react'

export function SiteFooter() {
  return (
    <footer className="border-t border-border">
      <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-4 px-4 py-10 text-sm text-muted-foreground sm:flex-row sm:px-6">
        <div className="flex items-center gap-2">
          <ShieldCheck className="size-4 text-primary" aria-hidden="true" />
          <span>{`© ${new Date().getFullYear()} RatShield`}</span>
        </div>
        <p>Remote access trojan protection for Windows.</p>
      </div>
    </footer>
  )
}
