import { useState } from 'react'
import { Container, Input, Button, Text, Spacer } from '@nextui-org/react'
import { setToken } from '../utils/auth'
import { useRouter } from 'next/router'

export default function Signup() {
  const [userId, setUserId] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [name, setName] = useState('')
  const [error, setError] = useState('')
  const router = useRouter()

  const handleSignup = async (e) => {
    e.preventDefault()
    setError('')

    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    try {
      const response = await fetch('http://localhost:5000/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ user_id: userId, password, name }),
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
      <Text h1>Sign Up</Text>
      <form onSubmit={handleSignup}>
        <Input
          label="Name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
        <Spacer y={1} />
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
        <Input.Password
          label="Confirm Password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          required
        />
        <Spacer y={1} />
        <Button type="submit">Sign Up</Button>
      </form>
      {error && <Text color="error">{error}</Text>}
    </Container>
  )
}