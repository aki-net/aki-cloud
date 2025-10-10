import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './contexts/AuthContext';
import Layout from './components/Layout';
import Login from './pages/Login';
import UserDashboard from './pages/UserDashboard';
import AdminDashboard from './pages/AdminDashboard';
import AdminDomains from './pages/AdminDomains';
import AdminUsers from './pages/AdminUsers';
import AdminInfrastructure from './pages/AdminInfrastructure';
import AdminExtensions from './pages/AdminExtensions';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  
  return <>{children}</>;
}

function App() {
  const { user } = useAuth();

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        {user?.role === 'admin' ? (
          <>
            <Route index element={<AdminDashboard />} />
            <Route path="domains" element={<AdminDomains />} />
            <Route path="users" element={<AdminUsers />} />
            <Route path="infrastructure" element={<AdminInfrastructure />} />
            <Route path="extensions/*" element={<AdminExtensions />} />
          </>
        ) : (
          <Route index element={<UserDashboard />} />
        )}
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;
