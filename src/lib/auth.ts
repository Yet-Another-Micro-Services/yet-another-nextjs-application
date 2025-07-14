import { NextAuthOptions } from "next-auth"
import GoogleProvider from "next-auth/providers/google"
import GitHubProvider from "next-auth/providers/github"
import CredentialsProvider from "next-auth/providers/credentials"

declare module "next-auth" {
  interface Session {
    user: {
      id: string
      name?: string | null
      email?: string | null
      image?: string | null
    }
    accessToken?: string
    provider?: string
    scope?: string
    backendUserId?: string
    backendAccessToken?: string
  }
}

export const authOptions: NextAuthOptions = {
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      authorization: {
        params: {
          scope: "openid email profile https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email"
        }
      }
    }),
    GitHubProvider({
      clientId: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
      authorization: {
        params: {
          scope: "read:user user:email"
        }
      }
    }),
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" }
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          return null
        }

        try {
          const response = await fetch(`${process.env.NEXT_PUBLIC_AUTH_SERVICE_URL || 'http://localhost:3001'}/api/auth/signin`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              email: credentials.email,
              password: credentials.password,
            }),
          })

          if (!response.ok) {
            return null
          }

          const data = await response.json()
          
          if (data.user && data.accessToken) {
            return {
              id: data.user.id,
              email: data.user.email,
              name: data.user.name,
              image: data.user.profilePicture,
              accessToken: data.accessToken,
              refreshToken: data.refreshToken,
            }
          }

          return null
        } catch (error) {
          console.error('Authentication error:', error)
          return null
        }
      }
    }),
  ],
  pages: {
    signIn: '/auth/signin',
  },
  callbacks: {
    async jwt({ token, user, account }) {
      if (account && user) {
        token.id = user.id
        
        // Handle credentials authentication (email/password)
        if (account.provider === 'credentials') {
          token.backendUserId = user.id
          token.backendAccessToken = (user as any).accessToken
          token.provider = 'credentials'
          return token
        }
        
        // Handle OAuth providers (Google, GitHub)
        token.accessToken = account.access_token
        token.refreshToken = account.refresh_token
        token.provider = account.provider
        token.scope = account.scope
        token.tokenType = account.token_type

        // Call backend auth-service to sync user data
        try {
          const backendResponse = await fetch(`${process.env.NEXT_PUBLIC_AUTH_SERVICE_URL || 'http://localhost:3001'}/api/auth/sync`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              provider: account.provider,
              providerId: account.providerAccountId,
              email: user.email,
              name: user.name,
              profilePicture: user.image,
              accessToken: account.access_token,
              refreshToken: account.refresh_token,
            }),
          })

          if (backendResponse.ok) {
            const backendUser = await backendResponse.json()
            console.log('User synced with backend:', backendUser.user.id)
            token.backendUserId = backendUser.user.id
            token.backendAccessToken = backendUser.accessToken
          } else {
            console.error('Failed to sync user with backend:', await backendResponse.text())
          }
        } catch (error) {
          console.error('Error syncing user with backend:', error)
        }
      }
      return token
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.id = token.id as string
        // Use backend access token for API calls
        session.accessToken = token.backendAccessToken as string
        session.provider = token.provider as string
        session.scope = token.scope as string
        // Add backend user info
        session.backendUserId = token.backendUserId as string
      }
      return session
    },
  },
  session: {
    strategy: "jwt",
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  secret: process.env.NEXTAUTH_SECRET,
}
