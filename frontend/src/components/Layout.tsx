import React from 'react';
import { Outlet, NavLink, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import './Layout.css';

export default function Layout() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const isAdmin = user?.role === 'admin';

  const adminNavItems = [
    { path: '/', label: 'Analytics', icon: '📊' },
    { path: '/domains', label: 'Domains', icon: '🌐' },
    { path: '/users', label: 'Users', icon: '👥' },
    { path: '/infrastructure', label: 'Infrastructure', icon: '🔧' },
    { path: '/extensions', label: 'Extensions', icon: '🚀' },
  ];

  return (
    <div className="layout">
      <header className="layout-header">
        <div className="header-brand">
          <span className="brand-icon">⚡</span>
          <span className="brand-text">aki-cloud</span>
        </div>

        {isAdmin && (
          <nav className="header-nav">
            {adminNavItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `nav-item ${isActive || (item.path === '/' && location.pathname === '/') ? 'nav-item-active' : ''}`
                }
              >
                <span className="nav-icon">{item.icon}</span>
                <span className="nav-label">{item.label}</span>
              </NavLink>
            ))}
          </nav>
        )}

        <div className="header-actions">
          <div className="user-info">
            <span className="user-role">{user?.role}</span>
            <span className="user-email">{user?.email}</span>
          </div>
          <button className="logout-btn" onClick={logout}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" />
              <polyline points="16 17 21 12 16 7" />
              <line x1="21" y1="12" x2="9" y2="12" />
            </svg>
            <span>Logout</span>
          </button>
        </div>
      </header>

      <main className="layout-main">
        <div className="main-container">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
