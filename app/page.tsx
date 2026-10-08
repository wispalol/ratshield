import { SiteHeader } from '@/components/site-header'
import { Hero } from '@/components/hero'
import { Threats } from '@/components/threats'
import { Features } from '@/components/features'
import { HowItWorks } from '@/components/how-it-works'
import { UnderTheHood } from '@/components/under-the-hood'
import { DownloadSection } from '@/components/download-section'
import { Faq } from '@/components/faq'
import { SiteFooter } from '@/components/site-footer'

export default function Page() {
  return (
    <>
      <SiteHeader />
      <main>
        <Hero />
        <Threats />
        <Features />
        <HowItWorks />
        <UnderTheHood />
        <DownloadSection />
        <Faq />
      </main>
      <SiteFooter />
    </>
  )
}
