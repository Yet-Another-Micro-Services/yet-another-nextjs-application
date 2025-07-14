"use client"

import { useSession, signIn, signOut } from "next-auth/react"
import { useState, useEffect } from "react"
import Image from "next/image"
import PasswordSetupModal from "../components/PasswordSetupModal"
import { useHasPassword } from "../hooks/useHasPassword"

// Password Management Component for existing users with passwords
function PasswordManagement() {
  const { data: session } = useSession()
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [showChangePassword, setShowChangePassword] = useState(false)
  const [showSetPassword, setShowSetPassword] = useState(false)
  const [hasPassword, setHasPassword] = useState<boolean | null>(null)

  const [changePasswordData, setChangePasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  })

  const [setPasswordData, setSetPasswordData] = useState({
    password: '',
    confirmPassword: ''
  })

  // Check if user has password
  useEffect(() => {
    const checkHasPassword = async () => {
      if (!session?.accessToken) return

      try {
        const response = await fetch(`${process.env.NEXT_PUBLIC_AUTH_SERVICE_URL || 'http://localhost:3001'}/api/auth/has-password`, {
          headers: {
            'Authorization': `Bearer ${(session as any).accessToken}`
          }
        })
        
        if (response.ok) {
          const data = await response.json()
          setHasPassword(data.hasPassword)
        }
      } catch (err) {
        console.error('Failed to check password status:', err)
      }
    }

    checkHasPassword()
  }, [session])

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError(null)
    setSuccess(null)

    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_AUTH_SERVICE_URL || 'http://localhost:3001'}/api/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${(session as any)?.accessToken}`
        },
        body: JSON.stringify(changePasswordData)
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.message || 'Failed to change password')
      }

      setSuccess('Password changed successfully!')
      setChangePasswordData({ currentPassword: '', newPassword: '', confirmPassword: '' })
      setShowChangePassword(false)
    } catch (err: any) {
      setError(err.message || 'Failed to change password')
    } finally {
      setIsLoading(false)
    }
  }

  const handleSetPassword = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError(null)
    setSuccess(null)

    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_AUTH_SERVICE_URL || 'http://localhost:3001'}/api/auth/set-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${(session as any)?.accessToken}`
        },
        body: JSON.stringify(setPasswordData)
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.message || 'Failed to set password')
      }

      setSuccess('Password set successfully!')
      setSetPasswordData({ password: '', confirmPassword: '' })
      setShowSetPassword(false)
      setHasPassword(true)
    } catch (err: any) {
      setError(err.message || 'Failed to set password')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <section className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-2xl font-semibold text-gray-900 mb-4">Password Management</h2>
      <p className="text-gray-600 mb-6">Manage your account password and security settings</p>
      
      {error && (
        <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-md">
          <p className="text-sm text-red-600">{error}</p>
        </div>
      )}
      
      {success && (
        <div className="mb-4 p-4 bg-green-50 border border-green-200 rounded-md">
          <p className="text-sm text-green-600">{success}</p>
        </div>
      )}

      {hasPassword ? (
        <div>
          <p className="text-gray-600 mb-4">You have a password set. You can change it here.</p>
          {!showChangePassword ? (
            <button
              onClick={() => setShowChangePassword(true)}
              className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
            >
              Change Password
            </button>
          ) : (
            <form onSubmit={handleChangePassword} className="space-y-4">
              <div>
                <label htmlFor="currentPassword" className="block text-sm font-medium text-gray-700">
                  Current Password
                </label>
                <input
                  type="password"
                  id="currentPassword"
                  value={changePasswordData.currentPassword}
                  onChange={(e) => setChangePasswordData(prev => ({ ...prev, currentPassword: e.target.value }))}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                  required
                />
              </div>
              
              <div>
                <label htmlFor="newPassword" className="block text-sm font-medium text-gray-700">
                  New Password
                </label>
                <input
                  type="password"
                  id="newPassword"
                  value={changePasswordData.newPassword}
                  onChange={(e) => setChangePasswordData(prev => ({ ...prev, newPassword: e.target.value }))}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                  required
                  minLength={8}
                />
                <p className="mt-1 text-sm text-gray-500">Must be at least 8 characters with uppercase, lowercase, number, and special character.</p>
              </div>
              
              <div>
                <label htmlFor="confirmNewPassword" className="block text-sm font-medium text-gray-700">
                  Confirm New Password
                </label>
                <input
                  type="password"
                  id="confirmNewPassword"
                  value={changePasswordData.confirmPassword}
                  onChange={(e) => setChangePasswordData(prev => ({ ...prev, confirmPassword: e.target.value }))}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                  required
                  minLength={8}
                />
              </div>
              
              <div className="flex space-x-3">
                <button
                  type="submit"
                  disabled={isLoading}
                  className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
                >
                  {isLoading ? 'Changing...' : 'Change Password'}
                </button>
                <button
                  type="button"
                  onClick={() => setShowChangePassword(false)}
                  className="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>
      ) : (
        <div>
          <p className="text-gray-600 mb-4">You signed in with a social account. Set a password to enable email/password login.</p>
          {!showSetPassword ? (
            <button
              onClick={() => setShowSetPassword(true)}
              className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
            >
              Set Password
            </button>
          ) : (
            <form onSubmit={handleSetPassword} className="space-y-4">
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                  New Password
                </label>
                <input
                  type="password"
                  id="password"
                  value={setPasswordData.password}
                  onChange={(e) => setSetPasswordData(prev => ({ ...prev, password: e.target.value }))}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                  required
                  minLength={8}
                />
                <p className="mt-1 text-sm text-gray-500">Must be at least 8 characters with uppercase, lowercase, number, and special character.</p>
              </div>
              
              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700">
                  Confirm Password
                </label>
                <input
                  type="password"
                  id="confirmPassword"
                  value={setPasswordData.confirmPassword}
                  onChange={(e) => setSetPasswordData(prev => ({ ...prev, confirmPassword: e.target.value }))}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                  required
                  minLength={8}
                />
              </div>
              
              <div className="flex space-x-3">
                <button
                  type="submit"
                  disabled={isLoading}
                  className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:opacity-50"
                >
                  {isLoading ? 'Setting...' : 'Set Password'}
                </button>
                <button
                  type="button"
                  onClick={() => setShowSetPassword(false)}
                  className="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>
      )}
    </section>
  )
}

export default function Home() {
  const { data: session, status } = useSession()
  const [isMinimumLoadingTime, setIsMinimumLoadingTime] = useState(true)
  const { hasPassword, isLoading: isLoadingPassword } = useHasPassword()

  // Ensure loading animation shows for at least 500ms
  useEffect(() => {
    const timer = setTimeout(() => {
      setIsMinimumLoadingTime(false)
    }, 500)

    return () => clearTimeout(timer)
  }, [])

  // Show loading if either session or password status is loading
  if (status === "loading" || isMinimumLoadingTime || isLoadingPassword) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="bg-white rounded-lg shadow-lg p-8 max-w-md w-full mx-4">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mx-auto mb-4"></div>
          <h1 className="text-2xl font-bold text-gray-900 text-center mb-2">Loading...</h1>
          <p className="text-gray-600 text-center">Please wait while we load your session.</p>
        </div>
      </div>
    )
  }

  if (session) {
    // Block access if user doesn't have a password (OAuth users who need to set password)
    if (hasPassword === false) {
      return (
        <PasswordSetupModal 
          onPasswordSet={() => {
            // Reload the page to update the session and hasPassword status
            window.location.reload()
          }}
        />
      )
    }

    // Normal dashboard for users with passwords
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
        {/* Header */}
        <header className="bg-white shadow-sm border-b">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
                <p className="text-lg text-gray-600 mt-1">Welcome back, {session.user?.name}!</p>
              </div>
              <div className="flex space-x-3">
                <button 
                  onClick={() => signOut()}
                  className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 transition-colors"
                >
                  Sign Out
                </button>
              </div>
            </div>
          </div>
        </header>

        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-8">
            {/* Profile Section */}
            <section className="bg-white rounded-lg shadow-md p-6">
              <h2 className="text-2xl font-semibold text-gray-900 mb-6">Profile</h2>
              <div className="flex items-center space-x-4">
                {session.user?.image && (
                  <div className="flex-shrink-0">
                    <Image 
                      src={session.user.image} 
                      alt="Profile" 
                      width={80} 
                      height={80}
                      className="rounded-full border-4 border-indigo-100"
                    />
                  </div>
                )}
                <div className="flex-1">
                  <h3 className="text-xl font-semibold text-gray-900">{session.user?.name || "User"}</h3>
                  <p className="text-gray-600 mb-2">{session.user?.email || "No email provided"}</p>
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                    Connected Account
                  </span>
                </div>
              </div>
            </section>

            {/* Password Management Section */}
            <PasswordManagement />

            {/* Session Information */}
            <section className="bg-white rounded-lg shadow-md p-6">
              <h2 className="text-2xl font-semibold text-gray-900 mb-4">Session Information</h2>
              <p className="text-gray-600 mb-6">Your current authentication session</p>
              
              <div className="space-y-4">
                <div className="border-l-4 border-indigo-500 pl-4">
                  <strong className="text-sm font-medium text-gray-900">Name:</strong>
                  <p className="text-gray-700 mt-1">{session.user?.name || "Not provided"}</p>
                </div>
                
                <div className="border-l-4 border-blue-500 pl-4">
                  <strong className="text-sm font-medium text-gray-900">Email:</strong>
                  <p className="text-gray-700 mt-1">{session.user?.email || "Not provided"}</p>
                </div>
                
                <div className="border-l-4 border-green-500 pl-4">
                  <strong className="text-sm font-medium text-gray-900">Session Status:</strong>
                  <div className="flex items-center mt-1">
                    <div className="h-2 w-2 bg-green-400 rounded-full mr-2"></div>
                    <p className="text-gray-700">Active</p>
                  </div>
                </div>
              </div>
            </section>
          </div>
        </main>
      </div>
    )
  }

  // Login page
  return <AuthForms />
}

// AuthForms component with tabs for OAuth and Email/Password authentication
function AuthForms() {
  const [activeTab, setActiveTab] = useState<'oauth' | 'email'>('oauth')
  const [emailMode, setEmailMode] = useState<'signin' | 'signup'>('signin')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  
  // Sign up form data
  const [signUpData, setSignUpData] = useState({
    email: '',
    username: '',
    name: '',
    password: '',
    confirmPassword: ''
  })

  // Sign in form data
  const [signInData, setSignInData] = useState({
    emailOrUsername: '',
    password: ''
  })

  // Form validation states
  const [touched, setTouched] = useState({
    email: false,
    name: false,
    username: false,
    password: false,
    confirmPassword: false,
    emailOrUsername: false,
    signInPassword: false
  })

  const [fieldErrors, setFieldErrors] = useState({
    email: '',
    name: '',
    username: '',
    password: '',
    confirmPassword: '',
    emailOrUsername: '',
    signInPassword: ''
  })

  // Validation functions
  const validateEmail = (email: string): string => {
    if (!email) return 'Email is required'
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return 'Invalid email format'
    return ''
  }

  const validateName = (name: string): string => {
    if (!name) return 'Name is required'
    if (name.length < 2) return 'Name must be at least 2 characters'
    if (name.length > 50) return 'Name must be less than 50 characters'
    return ''
  }

  const validateUsername = (username: string): string => {
    if (!username) return 'Username is required'
    if (username.length < 3) return 'Username must be at least 3 characters'
    if (username.length > 20) return 'Username must be less than 20 characters'
    if (!/^[a-zA-Z0-9_.-]+$/.test(username)) return 'Username can only contain letters, numbers, dots, hyphens, and underscores'
    if (/^[.-]|[.-]$/.test(username)) return 'Username cannot start or end with dots or hyphens'
    return ''
  }

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

  const validateEmailOrUsername = (value: string): string => {
    if (!value) return 'Email or username is required'
    // Check if it looks like an email
    if (value.includes('@')) {
      return validateEmail(value)
    } else {
      // Validate as username
      if (value.length < 3) return 'Username must be at least 3 characters'
      if (value.length > 20) return 'Username must be less than 20 characters'
      if (!/^[a-zA-Z0-9_.-]+$/.test(value)) return 'Username can only contain letters, numbers, dots, hyphens, and underscores'
    }
    return ''
  }

  const validateSignInPassword = (password: string): string => {
    if (!password) return 'Password is required'
    return ''
  }

  // Real-time validation handlers
  const handleSignUpChange = (field: string, value: string) => {
    setSignUpData(prev => ({ ...prev, [field]: value }))
    
    // Mark field as touched
    setTouched(prev => ({ ...prev, [field]: true }))
    
    // Validate field
    let error = ''
    switch (field) {
      case 'email':
        error = validateEmail(value)
        break
      case 'name':
        error = validateName(value)
        break
      case 'username':
        error = validateUsername(value)
        break
      case 'password':
        error = validatePassword(value)
        // Also revalidate confirm password if it exists
        if (signUpData.confirmPassword && touched.confirmPassword) {
          const confirmError = validateConfirmPassword(value, signUpData.confirmPassword)
          setFieldErrors(prev => ({ ...prev, confirmPassword: confirmError }))
        }
        break
      case 'confirmPassword':
        error = validateConfirmPassword(signUpData.password, value)
        break
    }
    
    setFieldErrors(prev => ({ ...prev, [field]: error }))
  }

  const handleSignInChange = (field: string, value: string) => {
    setSignInData(prev => ({ ...prev, [field]: value }))
    
    // Mark field as touched
    const touchedField = field === 'password' ? 'signInPassword' : field
    setTouched(prev => ({ ...prev, [touchedField]: true }))
    
    // Validate field
    let error = ''
    switch (field) {
      case 'emailOrUsername':
        error = validateEmailOrUsername(value)
        break
      case 'password':
        error = validateSignInPassword(value)
        break
    }
    
    const errorField = field === 'password' ? 'signInPassword' : field
    setFieldErrors(prev => ({ ...prev, [errorField]: error }))
  }

  // Helper function to determine if field has error and should show red border
  const getFieldClasses = (fieldName: keyof typeof touched, baseClasses: string): string => {
    const hasError = touched[fieldName] && fieldErrors[fieldName as keyof typeof fieldErrors]
    return hasError 
      ? `${baseClasses} border-red-500 focus:border-red-500 focus:ring-red-500`
      : `${baseClasses} border-gray-300 focus:border-indigo-500 focus:ring-indigo-500`
  }

  const handleOAuthSignIn = async (provider: string) => {
    setIsLoading(true)
    setError(null)
    try {
      await signIn(provider, { 
        callbackUrl: '/',
        redirect: true 
      })
    } catch (err) {
      setError('Failed to sign in. Please try again.')
      setIsLoading(false)
    }
  }

  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError(null)
    setSuccess(null)

    // Mark all fields as touched for validation
    setTouched({
      ...touched,
      email: true,
      name: true,
      username: true,
      password: true,
      confirmPassword: true
    })

    // Validate all fields
    const emailError = validateEmail(signUpData.email)
    const nameError = validateName(signUpData.name)
    const usernameError = validateUsername(signUpData.username)
    const passwordError = validatePassword(signUpData.password)
    const confirmPasswordError = validateConfirmPassword(signUpData.password, signUpData.confirmPassword)

    const newFieldErrors = {
      ...fieldErrors,
      email: emailError,
      name: nameError,
      username: usernameError,
      password: passwordError,
      confirmPassword: confirmPasswordError
    }

    setFieldErrors(newFieldErrors)

    // Check if there are any validation errors
    const hasErrors = Object.values(newFieldErrors).some(error => error !== '')
    if (hasErrors) {
      setError('Please fix the validation errors before submitting')
      setIsLoading(false)
      return
    }

    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_AUTH_SERVICE_URL || 'http://localhost:3001'}/api/auth/signup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: signUpData.email,
          username: signUpData.username || undefined,
          name: signUpData.name,
          password: signUpData.password
        })
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.message || 'Sign up failed')
      }

      const data = await response.json()
      setSuccess('Account created successfully! Please sign in.')
      setEmailMode('signin')
      setSignUpData({
        email: '',
        username: '',
        name: '',
        password: '',
        confirmPassword: ''
      })

      // Reset touched and errors
      setTouched({
        email: false,
        name: false,
        username: false,
        password: false,
        confirmPassword: false,
        emailOrUsername: false,
        signInPassword: false
      })
      setFieldErrors({
        email: '',
        name: '',
        username: '',
        password: '',
        confirmPassword: '',
        emailOrUsername: '',
        signInPassword: ''
      })
    } catch (err: any) {
      setError(err.message || 'An error occurred during sign up')
    } finally {
      setIsLoading(false)
    }
  }

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError(null)
    setSuccess(null)

    // Mark all fields as touched for validation
    setTouched({
      ...touched,
      emailOrUsername: true,
      signInPassword: true
    })

    // Validate all fields
    const emailOrUsernameError = validateEmailOrUsername(signInData.emailOrUsername)
    const passwordError = validateSignInPassword(signInData.password)

    const newFieldErrors = {
      ...fieldErrors,
      emailOrUsername: emailOrUsernameError,
      signInPassword: passwordError
    }

    setFieldErrors(newFieldErrors)

    // Check if there are any validation errors
    if (emailOrUsernameError || passwordError) {
      setError('Please fix the validation errors before submitting')
      setIsLoading(false)
      return
    }

    try {
      const result = await signIn('credentials', {
        email: signInData.emailOrUsername,
        password: signInData.password,
        redirect: false
      })

      if (result?.error) {
        setError('Invalid email/username or password')
      } else if (result?.ok) {
        window.location.href = '/'
      }
    } catch (err: any) {
      setError('Failed to sign in. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
      <div className="bg-white rounded-lg shadow-lg p-8 max-w-md w-full mx-4">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Welcome to YASS</h1>
          <p className="text-gray-600">
            {activeTab === 'oauth' 
              ? 'Sign in to your account with' 
              : (emailMode === 'signin' 
                ? 'Sign in to your account with' 
                : 'Create your account'
              )
            }
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="flex mb-6 bg-gray-100 rounded-lg p-1">
          <button
            onClick={() => setActiveTab('oauth')}
            className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
              activeTab === 'oauth'
                ? 'bg-white text-gray-900 shadow-sm'
                : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            Social Login
          </button>
          <button
            onClick={() => setActiveTab('email')}
            className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
              activeTab === 'email'
                ? 'bg-white text-gray-900 shadow-sm'
                : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            Email & Password
          </button>
        </div>

        {/* Success Message */}
        {success && (
          <div className="mb-4 p-4 bg-green-50 border border-green-200 rounded-md">
            <p className="text-sm text-green-600">{success}</p>
          </div>
        )}

        {/* Error Message */}
        {error && (
          <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-md">
            <p className="text-sm text-red-600">{error}</p>
          </div>
        )}

        {/* Content area with fixed minimum height */}
        <div className="h-[550px] overflow-y-auto">
          {activeTab === 'oauth' ? (
            <div className="space-y-3">
              <button
                onClick={() => handleOAuthSignIn('google')}
                disabled={isLoading}
                className="w-full flex items-center justify-center px-3 py-2 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <svg className="w-5 h-5 mr-3" viewBox="0 0 24 24">
                  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                </svg>
                {isLoading ? 'Signing in...' : 'Continue with Google'}
              </button>

              <button
                onClick={() => handleOAuthSignIn('github')}
                disabled={isLoading}
                className="w-full flex items-center justify-center px-3 py-2 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <svg className="w-5 h-5 mr-3" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 0C5.374 0 0 5.373 0 12 0 17.302 3.438 21.8 8.207 23.387c.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/>
                </svg>
                {isLoading ? 'Signing in...' : 'Continue with GitHub'}
              </button>
            </div>
          ) : (
          <div>
            {/* Email/Password Tab Sub-navigation */}
            <div className="flex mb-4 bg-gray-50 rounded-lg p-1">
              <button
                onClick={() => setEmailMode('signin')}
                className={`flex-1 py-2 px-3 rounded-md text-sm font-medium transition-colors ${
                  emailMode === 'signin'
                    ? 'bg-white text-gray-900 shadow-sm'
                    : 'text-gray-500 hover:text-gray-700'
                }`}
              >
                Sign In
              </button>
              <button
                onClick={() => setEmailMode('signup')}
                className={`flex-1 py-2 px-3 rounded-md text-sm font-medium transition-colors ${
                  emailMode === 'signup'
                    ? 'bg-white text-gray-900 shadow-sm'
                    : 'text-gray-500 hover:text-gray-700'
                }`}
              >
                Sign Up
              </button>
            </div>

            {/* Email/Password form content with fixed height */}
            <div className="h-[450px] overflow-y-auto">
              {emailMode === 'signin' ? (
              <form onSubmit={handleSignIn} className="space-y-3">
                <div>
                  <label htmlFor="emailOrUsername" className="block text-sm font-medium text-gray-700 mb-1">
                    Email or Username
                  </label>
                  <input
                    type="text"
                    id="emailOrUsername"
                    value={signInData.emailOrUsername}
                    onChange={(e) => handleSignInChange('emailOrUsername', e.target.value)}
                    onBlur={() => setTouched(prev => ({ ...prev, emailOrUsername: true }))}
                    className={getFieldClasses('emailOrUsername', "w-full px-2 py-1.5 border rounded-md shadow-sm focus:outline-none focus:ring-2 text-sm")}
                    required
                    disabled={isLoading}
                    placeholder="Enter your email or username"
                  />
                  {touched.emailOrUsername && fieldErrors.emailOrUsername && (
                    <p className="mt-1 text-xs text-red-600">{fieldErrors.emailOrUsername}</p>
                  )}
                </div>
                
                <div>
                  <label htmlFor="signInPassword" className="block text-sm font-medium text-gray-700 mb-1">
                    Password
                  </label>
                  <input
                    type="password"
                    id="signInPassword"
                    value={signInData.password}
                    onChange={(e) => handleSignInChange('password', e.target.value)}
                    onBlur={() => setTouched(prev => ({ ...prev, signInPassword: true }))}
                    className={getFieldClasses('signInPassword', "w-full px-2 py-1.5 border rounded-md shadow-sm focus:outline-none focus:ring-2 text-sm")}
                    required
                    disabled={isLoading}
                    placeholder="Enter your password"
                  />
                  {touched.signInPassword && fieldErrors.signInPassword && (
                    <p className="mt-1 text-xs text-red-600">{fieldErrors.signInPassword}</p>
                  )}
                </div>
                
                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full flex justify-center py-1.5 px-3 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isLoading ? 'Signing in...' : 'Sign In'}
                </button>
              </form>
            ) : (
              <form onSubmit={handleSignUp} className="space-y-3">
                <div>
                  <label htmlFor="signupEmail" className="block text-sm font-medium text-gray-700 mb-1">
                    Email Address *
                  </label>
                  <input
                    type="email"
                    id="signupEmail"
                    value={signUpData.email}
                    onChange={(e) => handleSignUpChange('email', e.target.value)}
                    onBlur={() => setTouched(prev => ({ ...prev, email: true }))}
                    className={getFieldClasses('email', "w-full px-2 py-1.5 border rounded-md shadow-sm focus:outline-none focus:ring-2 text-sm")}
                    required
                    disabled={isLoading}
                    placeholder="Enter your email address"
                  />
                  {touched.email && fieldErrors.email && (
                    <p className="mt-1 text-xs text-red-600">{fieldErrors.email}</p>
                  )}
                </div>

                <div>
                  <label htmlFor="signupName" className="block text-sm font-medium text-gray-700 mb-1">
                    Full Name *
                  </label>
                  <input
                    type="text"
                    id="signupName"
                    value={signUpData.name}
                    onChange={(e) => handleSignUpChange('name', e.target.value)}
                    onBlur={() => setTouched(prev => ({ ...prev, name: true }))}
                    className={getFieldClasses('name', "w-full px-2 py-1.5 border rounded-md shadow-sm focus:outline-none focus:ring-2 text-sm")}
                    required
                    disabled={isLoading}
                    placeholder="Enter your full name"
                  />
                  {touched.name && fieldErrors.name && (
                    <p className="mt-1 text-xs text-red-600">{fieldErrors.name}</p>
                  )}
                </div>

                <div>
                  <label htmlFor="signupUsername" className="block text-sm font-medium text-gray-700 mb-1">
                    Username *
                  </label>
                  <input
                    type="text"
                    id="signupUsername"
                    value={signUpData.username}
                    onChange={(e) => handleSignUpChange('username', e.target.value)}
                    onBlur={() => setTouched(prev => ({ ...prev, username: true }))}
                    className={getFieldClasses('username', "w-full px-2 py-1.5 border rounded-md shadow-sm focus:outline-none focus:ring-2 text-sm")}
                    required
                    disabled={isLoading}
                    placeholder="Choose a username"
                  />
                  {touched.username && fieldErrors.username && (
                    <p className="mt-1 text-xs text-red-600">{fieldErrors.username}</p>
                  )}
                </div>

                <div>
                  <label htmlFor="signupPassword" className="block text-sm font-medium text-gray-700 mb-1">
                    Password *
                  </label>
                  <input
                    type="password"
                    id="signupPassword"
                    value={signUpData.password}
                    onChange={(e) => handleSignUpChange('password', e.target.value)}
                    onBlur={() => setTouched(prev => ({ ...prev, password: true }))}
                    className={getFieldClasses('password', "w-full px-2 py-1.5 border rounded-md shadow-sm focus:outline-none focus:ring-2 text-sm")}
                    required
                    disabled={isLoading}
                    placeholder="Create a password"
                  />
                  {touched.password && fieldErrors.password && (
                    <p className="mt-1 text-xs text-red-600">{fieldErrors.password}</p>
                  )}
                  <p className="mt-1 text-xs text-gray-500">Must be at least 8 characters with uppercase, lowercase, number, and special character.</p>
                </div>

                <div>
                  <label htmlFor="signupConfirmPassword" className="block text-sm font-medium text-gray-700 mb-1">
                    Confirm Password *
                  </label>
                  <input
                    type="password"
                    id="signupConfirmPassword"
                    value={signUpData.confirmPassword}
                    onChange={(e) => handleSignUpChange('confirmPassword', e.target.value)}
                    onBlur={() => setTouched(prev => ({ ...prev, confirmPassword: true }))}
                    className={getFieldClasses('confirmPassword', "w-full px-2 py-1.5 border rounded-md shadow-sm focus:outline-none focus:ring-2 text-sm")}
                    required
                    disabled={isLoading}
                    placeholder="Confirm your password"
                  />
                  {touched.confirmPassword && fieldErrors.confirmPassword && (
                    <p className="mt-1 text-xs text-red-600">{fieldErrors.confirmPassword}</p>
                  )}
                </div>
                
                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full flex justify-center py-1.5 px-3 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isLoading ? 'Creating account...' : 'Create Account'}
                </button>
              </form>
            )}
            </div>
          </div>
        )}
        </div>

        <div className="mt-6 text-center">
          <p className="text-xs text-gray-500">
            By {emailMode === 'signin' ? 'signing in' : 'signing up'}, you agree to our terms of service and privacy policy.
          </p>
        </div>
      </div>
    </div>
  )
}
