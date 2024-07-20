import { Button, Container, Text, Spacer } from '@nextui-org/react'
import Link from 'next/link'

export default function Home() {
  const handleGoogleLogin = () => {
    window.location.href = 'http://localhost:5000/google/login'
  }

  const handleFacebookLogin = () => {
    window.location.href = 'http://localhost:5000/facebook/login'
  }

  return (
    <Container>
      <Text h1>Welcome to OAuth Example</Text>
      <Button onClick={handleGoogleLogin}>Login with Google</Button>
      <Spacer y={1} />
      <Button onClick={handleFacebookLogin}>Login with Facebook</Button>
      <Spacer y={1} />
      <Link href="/login">
        <Button>Login with Email/Mobile</Button>
      </Link>
      <Spacer y={1} />
      <Link href="/signup">
        <Button>Sign Up</Button>
      </Link>
      <Spacer y={1} />
      <Link href="/check-login">
        <Button>Check Login Status</Button>
      </Link>
    </Container>
  )
}