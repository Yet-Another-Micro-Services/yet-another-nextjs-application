import type { Metadata } from "next";
import Providers from "./providers";
import './globals.css'

export const metadata: Metadata = {
  title: "Social Auth App - Plain HTML",
  description: "Next.js app with Google and GitHub authentication - No styling",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <Providers>
          {children}
        </Providers>
      </body>
    </html>
  );
}
