import { useEffect, useState } from 'react'
import { Container, Text, Loading } from '@nextui-org/react'
import { getToken } from '../utils/auth'

export default function CheckLogin() {
  const [loginStatus, setLoginStatus] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const token = getToken()
    if (!token) {
      setLoginStatus({ logged_in: false })
      setLoading(false)
      return
    }

    fetch('http://localhost:5000/check_login', {
      headers: {
        'Authorization': token
      }
    })
      .then(response => response.json())
      .then(data => {
        setLoginStatus(data)
        setLoading(false)
      })
      .catch(error => {
        console.error('Error:', error)
        setLoading(false)
      })
  }, [])

  if (loading) {
    return <Loading>Checking login status...</Loading>
  }

  return (
    <Container>
      <Text h1>Login Status</Text>
      {loginStatus.logged_in ? (
        <Text>Welcome, {loginStatus.name}! You are logged in.</Text>
      ) : (
        <Text>You are not logged in.</Text>
      )}
    </Container>
  )
}