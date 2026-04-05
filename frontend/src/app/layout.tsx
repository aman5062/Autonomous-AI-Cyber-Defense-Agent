import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'AI Cyber Defense Agent',
  description: 'Autonomous AI-powered cybersecurity defense system',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
