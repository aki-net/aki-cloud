import { FormEvent, useEffect, useState } from 'react';
import {
  createUser,
  deleteNode,
  deleteUser,
  fetchEdges,
  fetchNameServers,
  fetchNodes,
  fetchUsers,
  rebuildServices,
  upsertNode,
} from '../services/api';
import { NameServerEntry, NodeRecord, UserRecord } from '../types';

interface NodeFormState {
  id?: string;
  name: string;
  ips: string;
  ns_ips: string;
  ns_label: string;
  ns_base_domain: string;
}

export const AdminDashboard = () => {
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [nodes, setNodes] = useState<NodeRecord[]>([]);
  const [nameservers, setNameservers] = useState<NameServerEntry[]>([]);
  const [edges, setEdges] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [userForm, setUserForm] = useState({ email: '', password: '', role: 'user' });
  const [nodeForm, setNodeForm] = useState<NodeFormState>({
    name: '',
    ips: '',
    ns_ips: '',
    ns_label: 'dns',
    ns_base_domain: '',
  });
  const [pending, setPending] = useState(false);

  const load = async () => {
    try {
      setLoading(true);
      const [usersData, nodesData, nsData, edgeData] = await Promise.all([
        fetchUsers(),
        fetchNodes(),
        fetchNameServers(),
        fetchEdges(),
      ]);
      setUsers(usersData);
      setNodes(nodesData);
      setNameservers(nsData);
      setEdges(edgeData);
    } catch (err) {
      setError('Failed to load infrastructure data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load().catch(() => null);
  }, []);

  const submitUser = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    try {
      const created = await createUser({
        email: userForm.email,
        password: userForm.password,
        role: userForm.role as 'admin' | 'user',
      });
      setUsers((prev) => [...prev, created]);
      setUserForm({ email: '', password: '', role: 'user' });
    } catch (err) {
      setError('Failed to create user');
    } finally {
      setPending(false);
    }
  };

  const removeUser = async (id: string) => {
    if (!window.confirm('Remove user?')) {
      return;
    }
    try {
      await deleteUser(id);
      setUsers((prev) => prev.filter((user) => user.id !== id));
    } catch (err) {
      setError('Failed to delete user');
    }
  };

  const submitNode = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    try {
      const nodePayload: NodeRecord = {
        id: nodeForm.id ?? '',
        name: nodeForm.name,
        ips: nodeForm.ips.split(',').map((ip) => ip.trim()).filter(Boolean),
        ns_ips: nodeForm.ns_ips.split(',').map((ip) => ip.trim()).filter(Boolean),
        ns_label: nodeForm.ns_label,
        ns_base_domain: nodeForm.ns_base_domain,
      };
      const saved = await upsertNode(nodePayload);
      setNodes((prev) => {
        const exists = prev.some((node) => node.id === saved.id);
        if (exists) {
          return prev.map((node) => (node.id === saved.id ? saved : node));
        }
        return [...prev, saved];
      });
      setNodeForm({ name: '', ips: '', ns_ips: '', ns_label: 'dns', ns_base_domain: '' });
    } catch (err) {
      setError('Failed to persist node');
    } finally {
      setPending(false);
    }
  };

  const editNode = (node: NodeRecord) => {
    setNodeForm({
      id: node.id,
      name: node.name,
      ips: node.ips.join(', '),
      ns_ips: node.ns_ips.join(', '),
      ns_label: node.ns_label ?? 'dns',
      ns_base_domain: node.ns_base_domain ?? '',
    });
  };

  const removeNode = async (node: NodeRecord) => {
    if (!window.confirm(`Remove node ${node.name}?`)) {
      return;
    }
    try {
      await deleteNode(node.id);
      setNodes((prev) => prev.filter((item) => item.id !== node.id));
    } catch (err) {
      setError('Failed to delete node');
    }
  };

  const triggerRebuild = async () => {
    try {
      setPending(true);
      await rebuildServices();
    } catch (err) {
      setError('Failed to trigger rebuild');
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="grid">
      <div className="card">
        <h2 className="section-title">Cluster Overview</h2>
        {loading ? (
          <p>Loading…</p>
        ) : (
          <div className="grid two">
            <div>
              <strong>Users</strong>
              <p>{users.length}</p>
            </div>
            <div>
              <strong>Nodes</strong>
              <p>{nodes.length}</p>
            </div>
            <div>
              <strong>Nameservers</strong>
              <p>{nameservers.length}</p>
            </div>
            <div>
              <strong>Edge IPs</strong>
              <p>{edges.length}</p>
            </div>
          </div>
        )}
        <button className="button" onClick={triggerRebuild} disabled={pending} style={{ marginTop: '1rem' }}>
          {pending ? 'Rebuilding…' : 'Rebuild CoreDNS & OpenResty'}
        </button>
      </div>

      <div className="card">
        <h3 className="section-title">Users</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Email</th>
              <th>Role</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {users.map((item) => (
              <tr key={item.id}>
                <td>{item.email}</td>
                <td>
                  <span className="badge">{item.role}</span>
                </td>
                <td>
                  <button className="button secondary" onClick={() => removeUser(item.id)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <form className="grid" onSubmit={submitUser} style={{ marginTop: '1rem' }}>
          <input
            className="input"
            placeholder="user@example.com"
            value={userForm.email}
            onChange={(e) => setUserForm((prev) => ({ ...prev, email: e.target.value }))}
            required
          />
          <input
            className="input"
            placeholder="temporary password"
            value={userForm.password}
            onChange={(e) => setUserForm((prev) => ({ ...prev, password: e.target.value }))}
            required
          />
          <select
            className="select"
            value={userForm.role}
            onChange={(e) => setUserForm((prev) => ({ ...prev, role: e.target.value }))}
          >
            <option value="user">user</option>
            <option value="admin">admin</option>
          </select>
          <button className="button" type="submit" disabled={pending}>
            Add user
          </button>
        </form>
      </div>

      <div className="card">
        <h3 className="section-title">Nodes</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>IPs</th>
              <th>NS IPs</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {nodes.map((node) => (
              <tr key={node.id}>
                <td>{node.name}</td>
                <td>{node.ips.join(', ')}</td>
                <td>{node.ns_ips.join(', ')}</td>
                <td className="flex right">
                  <button className="button secondary" onClick={() => editNode(node)}>
                    Edit
                  </button>
                  <button className="button secondary" onClick={() => removeNode(node)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <form onSubmit={submitNode} style={{ marginTop: '1rem' }}>
          <input
            className="input"
            placeholder="Node name"
            value={nodeForm.name}
            onChange={(e) => setNodeForm((prev) => ({ ...prev, name: e.target.value }))}
            required
          />
          <input
            className="input"
            placeholder="IPs (comma separated)"
            value={nodeForm.ips}
            onChange={(e) => setNodeForm((prev) => ({ ...prev, ips: e.target.value }))}
            required
          />
          <input
            className="input"
            placeholder="NS IPs (comma separated)"
            value={nodeForm.ns_ips}
            onChange={(e) => setNodeForm((prev) => ({ ...prev, ns_ips: e.target.value }))}
          />
          <div className="grid two">
            <input
              className="input"
              placeholder="NS label"
              value={nodeForm.ns_label}
              onChange={(e) => setNodeForm((prev) => ({ ...prev, ns_label: e.target.value }))}
            />
            <input
              className="input"
              placeholder="NS base domain"
              value={nodeForm.ns_base_domain}
              onChange={(e) => setNodeForm((prev) => ({ ...prev, ns_base_domain: e.target.value }))}
            />
          </div>
          <button className="button" type="submit" disabled={pending}>
            {nodeForm.id ? 'Update node' : 'Add node'}
          </button>
        </form>
      </div>

      <div className="card">
        <h3 className="section-title">Active Nameservers</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Node</th>
              <th>Hostname</th>
              <th>IPv4</th>
            </tr>
          </thead>
          <tbody>
            {nameservers.map((entry) => (
              <tr key={`${entry.node_id}-${entry.ipv4}`}>
                <td>{entry.name}</td>
                <td>{entry.fqdn}</td>
                <td>{entry.ipv4}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {error && <div className="alert">{error}</div>}
    </div>
  );
};
