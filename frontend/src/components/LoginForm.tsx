import { FormEvent, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../providers/AuthProvider';

export const LoginForm = () => {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/');
    }
  }, [isAuthenticated, navigate]);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await login({ email, password });
    } catch (err) {
      setError('Login failed. Check your credentials.');
    } finally {
      setPending(false);
    }
  };

  return (
    <form className="card" onSubmit={onSubmit} style={{ maxWidth: 420, width: '100%' }}>
      <h2>Sign in</h2>
      <p style={{ color: '#64748b', marginBottom: '1rem' }}>Welcome back. Enter your credentials to continue.</p>
      {error && <div className="alert" role="alert">{error}</div>}
      <label>
        Email
        <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
      </label>
      <label>
        Password
        <input
          className="input"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </label>
      <button className="button" type="submit" disabled={pending}>
        {pending ? 'Signing in…' : 'Sign in'}
      </button>
      <p style={{ fontSize: '0.85rem', color: '#64748b', marginTop: '1rem' }}>
        Changes may take up to 20 seconds to propagate across the cluster.
      </p>
    </form>
  );
};
