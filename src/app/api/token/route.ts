import { getServerSession } from "next-auth/next"
import { authOptions } from "@/lib/auth"
import { getToken } from "next-auth/jwt"
import { NextRequest, NextResponse } from "next/server"
import { cookies } from "next/headers"

export async function GET(request: NextRequest) {
  try {
    // Get session
    const session = await getServerSession(authOptions)
    
    // Get JWT token (this is the actual JWT)
    const token = await getToken({ 
      req: request, 
      secret: process.env.NEXTAUTH_SECRET 
    })

    if (!session || !token) {
      return NextResponse.json({ error: "No active session" }, { status: 401 })
    }

    // Get the raw JWT token from cookies
    const cookieStore = await cookies()
    const sessionTokenCookie = cookieStore.get('next-auth.session-token') || 
                              cookieStore.get('__Secure-next-auth.session-token')
    
    const rawJWT = sessionTokenCookie?.value || null

    return NextResponse.json({
      session,
      decodedToken: token, // This is the decoded JWT payload
      rawJWT, // This is the actual JWT string that can be decoded on jwt.io
      tokenInfo: {
        // JWT standard claims
        sub: token.sub, // Subject (user ID)
        iat: token.iat, // Issued at
        exp: token.exp, // Expires at
        jti: token.jti, // JWT ID
        
        // Custom claims
        name: token.name,
        email: token.email,
        picture: token.picture,
        provider: token.provider,
        scope: token.scope,
        accessToken: token.accessToken ? "***hidden***" : undefined, // Hide sensitive data
        
        // Computed values
        issuedAtDate: token.iat ? new Date((token.iat as number) * 1000).toISOString() : undefined,
        expiresAtDate: token.exp ? new Date((token.exp as number) * 1000).toISOString() : undefined,
        timeUntilExpiry: token.exp ? Math.max(0, (token.exp as number) * 1000 - Date.now()) : undefined,
      }
    })
  } catch (error) {
    console.error("Error getting token:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
