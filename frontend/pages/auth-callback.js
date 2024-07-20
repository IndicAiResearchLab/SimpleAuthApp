import { useEffect } from 'react'
import { useRouter } from 'next/router'
import { setToken } from '../utils/auth'

export default function AuthCallback() {
  const router = useRouter()

  useEffect(() => {
    const { token } = router.query
    if (token) {
      setToken(token)
      router.push('/profile')
    }
  }, [router.query])

  return <div>Authenticating...</div>
}