import Cookies from 'js-cookie'

export const setToken = (token) => {
  Cookies.set('token', token)
}

export const getToken = () => {
  return Cookies.get('token')
}

export const removeToken = () => {
  Cookies.remove('token')
}

export const logout = async () => {
  const token = getToken()
  if (token) {
    try {
      await fetch('http://localhost:5000/logout', {
        method: 'POST',
        headers: {
          'Authorization': token
        }
      })
    } catch (error) {
      console.error('Error during logout:', error)
    }
  }
  removeToken()
}