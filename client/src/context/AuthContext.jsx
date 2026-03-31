import { createContext, useContext, useState, useEffect, useCallback } from 'react';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [accessToken, setAccessToken] = useState(() => sessionStorage.getItem('access_token'));
  const [refreshToken, setRefreshToken] = useState(() => sessionStorage.getItem('refresh_token'));

  // Sync to sessionStorage when tokens change
  useEffect(() => {
    if (accessToken) {
      sessionStorage.setItem('access_token', accessToken);
    } else {
      sessionStorage.removeItem('access_token');
    }
  }, [accessToken]);

  useEffect(() => {
    if (refreshToken) {
      sessionStorage.setItem('refresh_token', refreshToken);
    } else {
      sessionStorage.removeItem('refresh_token');
    }
  }, [refreshToken]);

  const login = useCallback((tokens) => {
    setAccessToken(tokens.access_token);
    setRefreshToken(tokens.refresh_token);
  }, []);

  const logout = useCallback(() => {
    setAccessToken(null);
    setRefreshToken(null);
    sessionStorage.clear();
  }, []);

  const isAuthenticated = Boolean(accessToken);

  return (
    <AuthContext.Provider value={{ accessToken, refreshToken, isAuthenticated, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
