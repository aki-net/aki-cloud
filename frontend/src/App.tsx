import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { useEffect } from 'react';
import { LoginForm } from './components/LoginForm';
import { useAuth } from './providers/AuthProvider';
import { UserDashboard } from './pages/UserDashboard';
import { AdminDashboard } from './pages/AdminDashboard';
import { setToken } from './services/api';

const ProtectedRoute = ({ children }: { children: JSX.Element }) => {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  return children;
};

const Dashboard = () => {
  const { user } = useAuth();
  if (!user) {
    return null;
  }
  return user.role === 'admin' ? <AdminDashboard /> : <UserDashboard />;
};

const Header = () => {
  const { user, logout, token } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    setToken(token ?? null);
  }, [token]);

  return (
    <header className="app-header">
      <div>
        <strong>aki-cloud control plane</strong>
        {user && <p style={{ margin: 0, fontSize: '0.85rem' }}>signed in as {user.email}</p>}
      </div>
      {user && (
        <button
          className="button secondary"
          onClick={() => {
            logout();
            navigate('/login');
          }}
        >
          Sign out
        </button>
      )}
    </header>
  );
};

const App = () => {
  return (
    <div className="app-shell">
      <Header />
      <main className="app-main">
        <Routes>
          <Route path="/login" element={<LoginForm />} />
          <Route
            path="/*"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
};

export default App;
