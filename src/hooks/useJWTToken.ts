"use client"

import { useSession } from "next-auth/react"
import { useEffect, useState } from "react"

interface DecodedToken {
  sub?: string
  name?: string
  email?: string
  picture?: string
  iat?: number
  exp?: number
  jti?: string
  [key: string]: unknown
}

interface TokenData {
  token: string | null
  decodedToken: DecodedToken | null
  scopes: string[]
  provider: string | null
}

export function useJWTToken() {
  const { data: session } = useSession()
  const [tokenData, setTokenData] = useState<TokenData>({
    token: null,
    decodedToken: null,
    scopes: [],
    provider: null
  })

  useEffect(() => {
    const getToken = async () => {
      if (session) {
        try {
          // Fetch the JWT token from our custom API endpoint
          const response = await fetch('/api/token')
          const data = await response.json()
          
          let decodedToken = null
          let scopes: string[] = []
          
          if (data.token) {
            decodedToken = decodeJWTPayload(JSON.stringify(data.token))
            
            // Extract scopes from different possible locations
            if (data.token.scope) {
              scopes = data.token.scope.split(' ')
            } else if (session.scope) {
              scopes = session.scope.split(' ')
            }
          }
          
          setTokenData({
            token: data.token ? JSON.stringify(data.token, null, 2) : null,
            decodedToken,
            scopes,
            provider: data.token?.provider || session.provider || null
          })
          
        } catch (error) {
          console.error('Error fetching token:', error)
        }
      }
    }

    getToken()
  }, [session])

  return { ...tokenData, session }
}

// Utility function to decode JWT payload (client-side only)
export function decodeJWTPayload(token: string) {
  try {
    const base64Url = token.split('.')[1]
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map(function(c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
        })
        .join('')
    )
    return JSON.parse(jsonPayload)
  } catch (error) {
    console.error('Error decoding JWT:', error)
    return null
  }
}
