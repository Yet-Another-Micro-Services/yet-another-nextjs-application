"use client"

import { useSession } from "next-auth/react"
import { useState } from "react"

interface PasswordSetupModalProps {
  onPasswordSet: () => void
}

export default function PasswordSetupModal({ onPasswordSet }: PasswordSetupModalProps) {
  const { data: session } = useSession()
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [passwordData, setPasswordData] = useState({
    password: '',
    confirmPassword: ''
  })

  const [fieldErrors, setFieldErrors] = useState({
    password: '',
    confirmPassword: ''
  })

  const [touched, setTouched] = useState({
    password: false,
    confirmPassword: false
  })

  // Validation functions
  const validatePassword = (password: string): string => {
    if (!password) return 'Password is required'
    if (password.length < 8) return 'Password must be at least 8 characters'
    if (password.length > 128) return 'Password must be less than 128 characters'
    if (!/(?=.*[a-z])/.test(password)) return 'Password must contain at least one lowercase letter'
    if (!/(?=.*[A-Z])/.test(password)) return 'Password must contain at least one uppercase letter'
    if (!/(?=.*\d)/.test(password)) return 'Password must contain at least one number'
    if (!/(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])/.test(password)) return 'Password must contain at least one special character'
    return ''
  }

  const validateConfirmPassword = (password: string, confirmPassword: string): string => {
    if (!confirmPassword) return 'Please confirm your password'
    if (password !== confirmPassword) return 'Passwords do not match'
    return ''
  }

  const handlePasswordChange = (field: 'password' | 'confirmPassword', value: string) => {
    setPasswordData(prev => ({ ...prev, [field]: value }))
    setTouched(prev => ({ ...prev, [field]: true }))
    
    // Validate field
    let error = ''
    switch (field) {
      case 'password':
        error = validatePassword(value)
        // Also revalidate confirm password if it exists
        if (passwordData.confirmPassword && touched.confirmPassword) {
          const confirmError = validateConfirmPassword(value, passwordData.confirmPassword)
          setFieldErrors(prev => ({ ...prev, confirmPassword: confirmError }))
        }
        break
      case 'confirmPassword':
        error = validateConfirmPassword(passwordData.password, value)
        break
    }
    
    setFieldErrors(prev => ({ ...prev, [field]: error }))
  }

  const getFieldClasses = (fieldName: 'password' | 'confirmPassword', baseClasses: string) => {
    const hasError = touched[fieldName] && fieldErrors[fieldName]
    return hasError 
      ? `${baseClasses} border-red-500 focus:border-red-500 focus:ring-red-500` 
      : `${baseClasses} border-gray-300 focus:border-indigo-500 focus:ring-indigo-500`
  }

  const handleSetPassword = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError(null)

    // Mark all fields as touched for validation
    setTouched({
      password: true,
      confirmPassword: true
    })

    // Validate all fields
    const passwordError = validatePassword(passwordData.password)
    const confirmPasswordError = validateConfirmPassword(passwordData.password, passwordData.confirmPassword)

    const newFieldErrors = {
      password: passwordError,
      confirmPassword: confirmPasswordError
    }

    setFieldErrors(newFieldErrors)

    // Check if there are any validation errors
    if (passwordError || confirmPasswordError) {
      setError('Please fix the validation errors before submitting')
      setIsLoading(false)
      return
    }

    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_AUTH_SERVICE_URL || 'http://localhost:3001'}/api/auth/set-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${(session as any)?.accessToken}`
        },
        body: JSON.stringify({
          password: passwordData.password,
          confirmPassword: passwordData.confirmPassword
        })
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.message || 'Failed to set password')
      }

      // Password set successfully - notify parent
      onPasswordSet()
    } catch (err: any) {
      setError(err.message || 'Failed to set password')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-2xl max-w-md w-full p-8">
        <div className="text-center mb-6">
          <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-indigo-100 mb-4">
            <svg className="h-6 w-6 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Set Up Your Password</h2>
          <p className="text-gray-600">To complete your account setup and access the dashboard, please set a password for your account.</p>
        </div>

        {error && (
          <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-md">
            <p className="text-sm text-red-600">{error}</p>
          </div>
        )}

        <form onSubmit={handleSetPassword} className="space-y-6">
          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
              New Password *
            </label>
            <input
              type="password"
              id="password"
              value={passwordData.password}
              onChange={(e) => handlePasswordChange('password', e.target.value)}
              onBlur={() => setTouched(prev => ({ ...prev, password: true }))}
              className={getFieldClasses('password', "w-full px-3 py-2 border rounded-md shadow-sm focus:outline-none focus:ring-2")}
              required
              disabled={isLoading}
              placeholder="Enter your password"
            />
            {touched.password && fieldErrors.password && (
              <p className="mt-1 text-sm text-red-600">{fieldErrors.password}</p>
            )}
            <p className="mt-1 text-xs text-gray-500">Must be at least 8 characters with uppercase, lowercase, number, and special character.</p>
          </div>
          
          <div>
            <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 mb-2">
              Confirm Password *
            </label>
            <input
              type="password"
              id="confirmPassword"
              value={passwordData.confirmPassword}
              onChange={(e) => handlePasswordChange('confirmPassword', e.target.value)}
              onBlur={() => setTouched(prev => ({ ...prev, confirmPassword: true }))}
              className={getFieldClasses('confirmPassword', "w-full px-3 py-2 border rounded-md shadow-sm focus:outline-none focus:ring-2")}
              required
              disabled={isLoading}
              placeholder="Confirm your password"
            />
            {touched.confirmPassword && fieldErrors.confirmPassword && (
              <p className="mt-1 text-sm text-red-600">{fieldErrors.confirmPassword}</p>
            )}
          </div>
          
          <button
            type="submit"
            disabled={isLoading}
            className="w-full flex justify-center py-3 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoading ? (
              <div className="flex items-center">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                Setting Password...
              </div>
            ) : (
              'Set Password & Continue'
            )}
          </button>
        </form>

        <div className="mt-6 pt-6 border-t border-gray-200">
          <p className="text-center text-xs text-gray-500">
            This password will allow you to sign in directly with your email in the future.
          </p>
        </div>
      </div>
    </div>
  )
}
