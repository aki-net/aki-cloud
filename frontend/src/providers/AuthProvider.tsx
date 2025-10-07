import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { loginRequest, setToken as setClientToken } from '../services/api';
import { AuthContextValue, LoginPayload, SessionUser } from '../types';

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

const STORAGE_KEY = 'aki-cloud-session';

export const AuthProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<SessionUser | null>(null);

  useEffect(() => {
    const stored = globalThis.localStorage?.getItem(STORAGE_KEY);
    if (stored) {
      try {
        const parsed = JSON.parse(stored) as { token: string; user: SessionUser };
        setToken(parsed.token);
        setUser(parsed.user);
        setClientToken(parsed.token);
      } catch (err) {
        console.warn('failed to restore session', err);
      }
    }
  }, []);

  const persist = (nextToken: string, nextUser: SessionUser) => {
    setToken(nextToken);
    setUser(nextUser);
    setClientToken(nextToken);
    globalThis.localStorage?.setItem(STORAGE_KEY, JSON.stringify({ token: nextToken, user: nextUser }));
  };

  const clear = () => {
    setToken(null);
    setUser(null);
    setClientToken(null);
    globalThis.localStorage?.removeItem(STORAGE_KEY);
  };

  const login = async (payload: LoginPayload) => {
    const response = await loginRequest(payload);
    persist(response.token, response.user);
    return response.user;
  };

  const value = useMemo<AuthContextValue>(
    () => ({
      token,
      user,
      isAuthenticated: Boolean(token && user),
      login,
      logout: clear,
    }),
    [token, user],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
