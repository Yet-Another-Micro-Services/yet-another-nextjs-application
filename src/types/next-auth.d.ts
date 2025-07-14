import NextAuth from "next-auth"

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
  }

  interface JWT {
    id?: string
    accessToken?: string
    refreshToken?: string
    provider?: string
    scope?: string
    tokenType?: string
    backendUserId?: string
    backendAccessToken?: string
  }
}
