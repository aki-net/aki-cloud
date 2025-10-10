import React, { useState, useEffect } from 'react';
import { users as usersApi } from '../api/client';
import { User, CreateUserPayload } from '../types';
import Table from '../components/ui/Table';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import Badge from '../components/ui/Badge';
import Card from '../components/ui/Card';
import toast from 'react-hot-toast';
import './AdminUsers.css';

export default function AdminUsers() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [showAddUser, setShowAddUser] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);

  useEffect(() => {
    loadUsers();
  }, []);

  const loadUsers = async () => {
    try {
      const data = await usersApi.list();
      setUsers(data);
    } catch (error) {
      toast.error('Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteUser = async (user: User) => {
    if (!confirm(`Delete user ${user.email}? This action cannot be undone.`)) return;

    try {
      await usersApi.delete(user.id);
      setUsers(users.filter(u => u.id !== user.id));
      toast.success(`Deleted user ${user.email}`);
    } catch (error) {
      toast.error('Failed to delete user');
    }
  };

  const filteredUsers = users.filter(u =>
    u.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
    u.role.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const columns = [
    {
      key: 'email',
      header: 'Email',
      accessor: (u: User) => (
        <div className="user-email-cell">
          <span className="user-email">{u.email}</span>
        </div>
      ),
    },
    {
      key: 'role',
      header: 'Role',
      accessor: (u: User) => (
        <Badge variant={u.role === 'admin' ? 'primary' : 'default'}>
          {u.role}
        </Badge>
      ),
      width: '120px',
    },
    {
      key: 'id',
      header: 'User ID',
      accessor: (u: User) => (
        <span className="user-id mono">{u.id}</span>
      ),
      width: '300px',
    },
    {
      key: 'actions',
      header: 'Actions',
      accessor: (u: User) => (
        <div className="actions-cell">
          <button
            className="action-btn"
            onClick={() => setEditingUser(u)}
            title="Edit user"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7" />
              <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z" />
            </svg>
          </button>
          <button
            className="action-btn action-btn-danger"
            onClick={() => handleDeleteUser(u)}
            title="Delete user"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="3 6 5 6 21 6" />
              <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
            </svg>
          </button>
        </div>
      ),
      width: '100px',
      align: 'center' as const,
    },
  ];

  return (
    <div className="admin-users">
      <div className="page-header">
        <div className="header-content">
          <h1>User Management</h1>
          <p className="subtitle">{users.length} registered users</p>
        </div>
        <div className="header-actions">
          <Input
            placeholder="Search users..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            icon={
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" />
                <path d="M21 21l-4.35-4.35" />
              </svg>
            }
          />
          <Button variant="primary" onClick={() => setShowAddUser(true)}>
            Add User
          </Button>
        </div>
      </div>

      <div className="stats-grid">
        <Card className="stat-card">
          <div className="stat-value">{users.filter(u => u.role === 'admin').length}</div>
          <div className="stat-label">Administrators</div>
        </Card>
        <Card className="stat-card">
          <div className="stat-value">{users.filter(u => u.role === 'user').length}</div>
          <div className="stat-label">Regular Users</div>
        </Card>
        <Card className="stat-card">
          <div className="stat-value">{users.length}</div>
          <div className="stat-label">Total Users</div>
        </Card>
      </div>

      <Card padding="none">
        <Table
          columns={columns}
          data={filteredUsers}
          keyExtractor={(u) => u.id}
          loading={loading}
          emptyMessage="No users found"
        />
      </Card>

      {(showAddUser || editingUser) && (
        <UserModal
          user={editingUser}
          onClose={() => {
            setShowAddUser(false);
            setEditingUser(null);
          }}
          onSave={loadUsers}
        />
      )}
    </div>
  );
}

function UserModal({
  user,
  onClose,
  onSave,
}: {
  user?: User | null;
  onClose: () => void;
  onSave: () => void;
}) {
  const [formData, setFormData] = useState<CreateUserPayload>({
    email: user?.email || '',
    password: '',
    role: user?.role || 'user',
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      if (user) {
        await usersApi.update(user.id, {
          ...formData,
          password: formData.password || undefined,
        });
        toast.success('User updated successfully');
      } else {
        await usersApi.create(formData);
        toast.success('User created successfully');
      }
      onSave();
      onClose();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to save user');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>{user ? 'Edit User' : 'Add User'}</h2>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>
        <form onSubmit={handleSubmit} className="modal-body">
          <Input
            type="email"
            label="Email"
            placeholder="user@example.com"
            value={formData.email}
            onChange={(e) => setFormData({ ...formData, email: e.target.value })}
            fullWidth
            required
            disabled={!!user}
          />

          <Input
            type="password"
            label={user ? 'New Password (leave empty to keep current)' : 'Password'}
            placeholder="••••••••"
            value={formData.password}
            onChange={(e) => setFormData({ ...formData, password: e.target.value })}
            fullWidth
            required={!user}
          />

          <div className="form-group">
            <label>Role</label>
            <div className="role-options">
              <label className="role-option">
                <input
                  type="radio"
                  name="role"
                  value="user"
                  checked={formData.role === 'user'}
                  onChange={(e) => setFormData({ ...formData, role: e.target.value as 'user' | 'admin' })}
                />
                <span className="role-label">
                  <strong>User</strong>
                  <small>Can manage their own domains</small>
                </span>
              </label>
              <label className="role-option">
                <input
                  type="radio"
                  name="role"
                  value="admin"
                  checked={formData.role === 'admin'}
                  onChange={(e) => setFormData({ ...formData, role: e.target.value as 'user' | 'admin' })}
                />
                <span className="role-label">
                  <strong>Admin</strong>
                  <small>Full system access</small>
                </span>
              </label>
            </div>
          </div>

          <div className="modal-actions">
            <Button variant="ghost" onClick={onClose} disabled={loading}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={loading}>
              {user ? 'Update User' : 'Create User'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
