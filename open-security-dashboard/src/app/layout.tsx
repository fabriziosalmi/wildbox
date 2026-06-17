import type { Metadata } from 'next'
import { Inter, JetBrains_Mono } from 'next/font/google'
import './globals.css'
import { Providers } from './providers'

const inter = Inter({ 
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
})

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-jetbrains-mono',
  display: 'swap',
})

export const metadata: Metadata = {
  title: 'Wildbox Security Dashboard',
  description: 'Comprehensive security operations center and threat intelligence platform',
  keywords: ['security', 'threat intelligence', 'cybersecurity', 'dashboard', 'SOC'],
  authors: [{ name: 'Wildbox Security' }],
  creator: 'Wildbox Security',
  publisher: 'Wildbox Security',
  formatDetection: {
    email: false,
    address: false,
    telephone: false,
  },
  metadataBase: new URL(process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'),
  openGraph: {
    title: 'Wildbox Security Dashboard',
    description: 'Comprehensive security operations center and threat intelligence platform',
    url: process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000',
    siteName: 'Wildbox Security',
    locale: 'en_US',
    type: 'website',
  },
  robots: {
    index: false,
    follow: false,
    googleBot: {
      index: false,
      follow: false,
    },
  },
  viewport: {
    width: 'device-width',
    initialScale: 1,
    maximumScale: 1,
  },
  icons: {
    // Only the SVG is shipped (public/icon.svg). An explicit icon link makes
    // browsers use it instead of auto-requesting a (missing) /favicon.ico.
    icon: [{ url: '/icon.svg', type: 'image/svg+xml' }],
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    // suppressHydrationWarning: the theme provider sets the light/dark class on
    // <html> on the client, which legitimately differs from the server render.
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable}`} suppressHydrationWarning>
      <body className="min-h-screen bg-background font-sans antialiased">
        <Providers>
          {children}
        </Providers>
      </body>
    </html>
  )
}
