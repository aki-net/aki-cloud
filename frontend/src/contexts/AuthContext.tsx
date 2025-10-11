import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { auth, setAuthToken, validateSession } from '../api/client';
import { User, LoginCredentials } from '../types';
import toast from 'react-hot-toast';

interface AuthContextValue {
  token: string | null;
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();
  const isInitialized = useRef(false);

  // Initialize auth token and validate session on mount
  useEffect(() => {
    if (isInitialized.current) return;
    isInitialized.current = true;
    
    const initAuth = async () => {
      const storedToken = localStorage.getItem('auth_token');
      const storedUser = localStorage.getItem('user');
      
      if (storedToken && storedUser) {
        try {
          const parsedUser = JSON.parse(storedUser);
          setToken(storedToken);
          setUser(parsedUser);
          setAuthToken(storedToken);
          
          // Validate in background, don't block
          validateSession().catch(() => {
            // Only clear if validation explicitly fails
            setToken(null);
            setUser(null);
            setAuthToken(null);
            localStorage.removeItem('auth_token');
            localStorage.removeItem('user');
          });
        } catch (error) {
          console.error('Failed to parse stored user:', error);
          localStorage.removeItem('auth_token');
          localStorage.removeItem('user');
        }
      }
      
      setIsLoading(false);
    };
    
    initAuth();
  }, []);

  // Update auth token when it changes
  useEffect(() => {
    if (token) {
      setAuthToken(token);
    }
  }, [token]);

  const login = useCallback(async (credentials: LoginCredentials) => {
    setIsLoading(true);
    try {
      const response = await auth.login(credentials);
      const { token: newToken, user: newUser } = response;
      
      // Set token first to authorize subsequent requests
      setAuthToken(newToken);
      
      // Store in state and localStorage
      setToken(newToken);
      setUser(newUser);
      localStorage.setItem('auth_token', newToken);
      localStorage.setItem('user', JSON.stringify(newUser));
      
      toast.success('Successfully logged in');
      
      navigate('/');
    } catch (error: any) {
      console.error('Login failed:', error);
      const errorMessage = error.response?.data?.error || error.message || 'Invalid credentials';
      toast.error(errorMessage);
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [navigate]);

  const logout = useCallback(() => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user');
    toast.success('Logged out successfully');
    navigate('/login');
  }, [navigate]);

  const value: AuthContextValue = {
    token,
    user,
    isAuthenticated: !!token && !!user,
    isLoading,
    login,
    logout,
  };

  // Don't render children until auth is initialized
  if (isLoading) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
        background: '#0a0b0f'
      }}>
        <div style={{ color: '#e9ecf5' }}>Loading...</div>
      </div>
    );
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
