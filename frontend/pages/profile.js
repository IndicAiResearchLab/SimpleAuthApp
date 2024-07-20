import { useEffect, useState } from 'react'
import { Container, Text, Loading, Button } from '@nextui-org/react'
import { getToken, logout } from '../utils/auth'
import { useRouter } from 'next/router'

export default function Profile() {
  const [profile, setProfile] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const router = useRouter()

  useEffect(() => {
    const token = getToken()
    if (!token) {
      router.push('/login')
      return
    }

    fetch('http://localhost:5000/profile', {
      headers: {
        'Authorization': token
      }
    })
      .then(response => response.json())
      .then(data => {
        if (data.error) {
          setError(data.error)
        } else {
          setProfile(data)
        }
        setLoading(false)
      })
      .catch(error => {
        console.error('Error:', error)
        setError('Failed to fetch profile data')
        setLoading(false)
      })
  }, [])

  const handleLogout = () => {
    logout()
    router.push('/')
  }

  if (loading) {
    return <Loading>Loading profile...</Loading>
  }

  if (error) {
    return (
      <Container>
        <Text h1>Error</Text>
        <Text>{error}</Text>
      </Container>
    )
  }

  return (
    <Container>
      <Text h1>Profile</Text>
      {profile && (
        <>
          <Text>Name: {profile.name}</Text>
          <Text>Email: {profile.email}</Text>
          <Text>Auth Provider: {profile.auth_provider}</Text>
          <Text>{profile.message}</Text>
          <Button onClick={handleLogout}>Logout</Button>
        </>
      )}
    </Container>
  )
}