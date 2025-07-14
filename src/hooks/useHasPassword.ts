import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'

export function useHasPassword() {
  const { data: session, status } = useSession()
  const [hasPassword, setHasPassword] = useState<boolean | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const checkPassword = async () => {
      // Only check if user is authenticated
      if (status !== 'authenticated' || !(session as any)?.accessToken) {
        setIsLoading(false)
        return
      }

      try {
        setIsLoading(true)
        setError(null)
        
        const response = await fetch(`${process.env.NEXT_PUBLIC_AUTH_SERVICE_URL || 'http://localhost:3001'}/api/auth/has-password`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${(session as any).accessToken}`,
            'Content-Type': 'application/json'
          }
        })

        if (!response.ok) {
          const errorData = await response.json()
          throw new Error(errorData.message || 'Failed to check password status')
        }

        const data = await response.json()
        setHasPassword(data.hasPassword)
      } catch (err: any) {
        console.error('Error checking password status:', err)
        setError(err.message || 'Failed to check password status')
        // Default to true to avoid blocking users if API fails
        setHasPassword(true)
      } finally {
        setIsLoading(false)
      }
    }

    checkPassword()
  }, [session, status])

  const refetch = () => {
    if (status === 'authenticated' && (session as any)?.accessToken) {
      const checkPassword = async () => {
        try {
          setIsLoading(true)
          setError(null)
          
          const response = await fetch(`${process.env.NEXT_PUBLIC_AUTH_SERVICE_URL || 'http://localhost:3001'}/api/auth/has-password`, {
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${(session as any).accessToken}`,
              'Content-Type': 'application/json'
            }
          })

          if (!response.ok) {
            const errorData = await response.json()
            throw new Error(errorData.message || 'Failed to check password status')
          }

          const data = await response.json()
          setHasPassword(data.hasPassword)
        } catch (err: any) {
          console.error('Error checking password status:', err)
          setError(err.message || 'Failed to check password status')
          // Default to true to avoid blocking users if API fails
          setHasPassword(true)
        } finally {
          setIsLoading(false)
        }
      }

      checkPassword()
    }
  }

  return {
    hasPassword,
    isLoading,
    error,
    refetch
  }
}
