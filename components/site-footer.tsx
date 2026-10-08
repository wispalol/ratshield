import { ShieldCheck } from 'lucide-react'
import { download } from '@/lib/site'

const links = [
  { href: '#features', label: 'Features' },
  { href: '#how-it-works', label: 'How it works' },
  { href: '#technical', label: 'Technical' },
  { href: '#download', label: 'Download' },
  { href: '#faq', label: 'FAQ' },
]

export function SiteFooter() {
  return (
    <footer className="border-t border-border">
      <div className="mx-auto flex max-w-6xl flex-col gap-8 px-4 py-12 sm:px-6 md:flex-row md:items-start md:justify-between">
        <div className="max-w-sm">
          <div className="flex items-center gap-2 font-semibold">
            <ShieldCheck className="size-5 text-primary" aria-hidden="true" />
            RatShield
          </div>
          <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
            Remote access trojan protection for Windows. Works alongside your existing antivirus.
          </p>
        </div>
        <nav aria-label="Footer">
          <ul className="flex flex-wrap gap-x-6 gap-y-2 text-sm text-muted-foreground">
            {links.map((link) => (
              <li key={link.href}>
                <a href={link.href} className="transition-colors hover:text-foreground">
                  {link.label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
      </div>
      <div className="border-t border-border">
        <div className="mx-auto flex max-w-6xl flex-col justify-between gap-2 px-4 py-6 font-mono text-xs text-muted-foreground sm:flex-row sm:px-6">
          <span>{`© ${new Date().getFullYear()} RatShield`}</span>
          <span>{`v${download.version} · ${download.platform}`}</span>
        </div>
      </div>
    </footer>
  )
}
