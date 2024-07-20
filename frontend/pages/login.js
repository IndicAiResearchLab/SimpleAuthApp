import { useState } from 'react'
import { Container, Input, Button, Text, Spacer } from '@nextui-org/react'
import { setToken } from '../utils/auth'
import { useRouter } from 'next/router'

export default function Login() {
  const [userId, setUserId] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const router = useRouter()

  const handleLogin = async (e) => {
    e.preventDefault()
    setError('')

    try {
      const response = await fetch('http://localhost:5000/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ user_id: userId, password }),
      })

      const data = await response.json()

      if (response.ok) {
        setToken(data.token)
        router.push('/profile')
      } else {
        setError(data.error)
      }
    } catch (error) {
      setError('An error occurred. Please try again.')
    }
  }

  return (
    <Container>
      <Text h1>Login</Text>
      <form onSubmit={handleLogin}>
        <Input
          label="Email or Mobile"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          required
        />
        <Spacer y={1} />
        <Input.Password
          label="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <Spacer y={1} />
        <Button type="submit">Login</Button>
      </form>
      {error && <Text color="error">{error}</Text>}
    </Container>
  )
}