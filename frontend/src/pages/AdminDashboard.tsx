import { FormEvent, useEffect, useMemo, useState } from 'react';
import {
  checkNameServers,
  createUser,
  deleteNode,
  deleteUser,
  fetchDomainOverview,
  fetchEdges,
  fetchNameServers,
  fetchNodes,
  fetchUsers,
  rebuildServices,
  upsertNode,
} from '../services/api';
import { DomainOverview, NameServerEntry, NameServerStatus, NodeRecord, UserRecord } from '../types';

interface NodeFormState {
  id?: string;
  name: string;
  ips: string;
  ns_ips: string;
  ns_label: string;
  ns_base_domain: string;
  api_endpoint: string;
}

interface DomainGroup {
  label: string;
  exists: boolean;
  domains: DomainOverview[];
}

export const AdminDashboard = () => {
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [nodes, setNodes] = useState<NodeRecord[]>([]);
  const [nameservers, setNameservers] = useState<NameServerEntry[]>([]);
  const [edges, setEdges] = useState<string[]>([]);
  const [domains, setDomains] = useState<DomainOverview[]>([]);
  const [nsStatus, setNsStatus] = useState<NameServerStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [userForm, setUserForm] = useState({ email: '', password: '', role: 'user' });
  const [nodeForm, setNodeForm] = useState<NodeFormState>({
    name: '',
    ips: '',
    ns_ips: '',
    ns_label: 'dns',
    ns_base_domain: '',
    api_endpoint: '',
  });
  const [pending, setPending] = useState(false);
  const [nsPending, setNsPending] = useState(false);

  const load = async () => {
    try {
      setLoading(true);
      const [usersData, nodesData, nsData, edgeData, domainData] = await Promise.all([
        fetchUsers(),
        fetchNodes(),
        fetchNameServers(),
        fetchEdges(),
        fetchDomainOverview(),
      ]);
      setUsers(usersData);
      setNodes(nodesData);
      setNameservers(nsData);
      setEdges(edgeData);
      setDomains(domainData);
    } catch (err) {
      setError('Failed to load infrastructure data');
    } finally {
      setLoading(false);
    }
  };

  const refreshDomainOverview = async () => {
    try {
      const data = await fetchDomainOverview();
      setDomains(data);
    } catch (err) {
      setError('Failed to refresh domain overview');
    }
  };

  const refreshNameServerStatus = async (guard?: { cancelled: boolean }) => {
    if (guard?.cancelled) {
      return;
    }
    setNsPending(true);
    try {
      const data = await checkNameServers();
      if (guard?.cancelled) {
        return;
      }
      setNsStatus(data);
    } catch (err) {
      if (!guard?.cancelled) {
        setError((prev) => prev ?? 'Failed to check nameservers');
      }
    } finally {
      if (!guard?.cancelled) {
        setNsPending(false);
      }
    }
  };

  useEffect(() => {
    const guard = { cancelled: false };
    const run = async () => {
      await load();
      if (guard.cancelled) {
        return;
      }
      await refreshNameServerStatus(guard);
    };
    run().catch(() => null);
    return () => {
      guard.cancelled = true;
    };
  }, []);

  const groupSortKey = (group: DomainGroup) => {
    return `${group.exists ? '0' : '1'}-${group.label}`;
  };

  const domainGroups = useMemo<DomainGroup[]>(() => {
    const groups = new Map<string, DomainGroup>();
    domains.forEach((domain) => {
      const label = domain.owner_email || domain.owner_id || 'unassigned';
      const key = label.toLowerCase();
      const entry = groups.get(key);
      if (entry) {
        entry.domains.push(domain);
        entry.exists = entry.exists || domain.owner_exists;
      } else {
        groups.set(key, {
          label,
          exists: domain.owner_exists,
          domains: [domain],
        });
      }
    });
    const list = Array.from(groups.values());
    list.forEach((group) => group.domains.sort((a, b) => a.domain.localeCompare(b.domain)));
    list.sort((a, b) => groupSortKey(a).localeCompare(groupSortKey(b)));
    return list;
  }, [domains]);

  const nsStatusMap = useMemo(() => {
    const map = new Map<string, NameServerStatus>();
    nsStatus.forEach((status) => {
      map.set(`${status.fqdn}|${status.ipv4}`, status);
    });
    return map;
  }, [nsStatus]);

  const formatDate = (value: string) => {
    if (!value) {
      return '—';
    }
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return '—';
    }
    return parsed.toLocaleString();
  };

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
      await refreshDomainOverview();
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
        name: nodeForm.name.trim(),
        ips: nodeForm.ips.split(',').map((ip) => ip.trim()).filter(Boolean),
        ns_ips: nodeForm.ns_ips.split(',').map((ip) => ip.trim()).filter(Boolean),
        ns_label: nodeForm.ns_label,
        ns_base_domain: nodeForm.ns_base_domain,
        api_endpoint: nodeForm.api_endpoint.trim(),
      };
      const saved = await upsertNode(nodePayload);
      setNodes((prev) => {
        const exists = prev.some((node) => node.id === saved.id);
        if (exists) {
          return prev.map((node) => (node.id === saved.id ? saved : node));
        }
        return [...prev, saved];
      });
      setNodeForm({ name: '', ips: '', ns_ips: '', ns_label: 'dns', ns_base_domain: '', api_endpoint: '' });
      await refreshNameServerStatus();
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
      api_endpoint: node.api_endpoint ?? '',
    });
  };

  const removeNode = async (node: NodeRecord) => {
    if (!window.confirm(`Remove node ${node.name}?`)) {
      return;
    }
    try {
      await deleteNode(node.id);
      setNodes((prev) => prev.filter((item) => item.id !== node.id));
      await refreshNameServerStatus();
    } catch (err) {
      setError('Failed to delete node');
    }
  };

  const triggerRebuild = async () => {
    try {
      setPending(true);
      await rebuildServices();
      await refreshNameServerStatus();
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
              <th>API Endpoint</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {nodes.map((node) => (
              <tr key={node.id}>
                <td>{node.name}</td>
                <td>{node.ips.join(', ')}</td>
                <td>{node.ns_ips.join(', ')}</td>
                <td>{node.api_endpoint ?? '—'}</td>
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
          <input
            className="input"
            placeholder="API endpoint (http://ip:port)"
            value={nodeForm.api_endpoint}
            onChange={(e) => setNodeForm((prev) => ({ ...prev, api_endpoint: e.target.value }))}
          />
          <button className="button" type="submit" disabled={pending}>
            {nodeForm.id ? 'Update node' : 'Add node'}
          </button>
        </form>
      </div>

      <div className="card">
        <h3 className="section-title">Domains by Owner</h3>
        {domainGroups.length === 0 ? (
          <p>No domains configured.</p>
        ) : (
          domainGroups.map((group) => (
            <div className="card nested" key={group.label}>
              <div className="group-header">
                <strong>{group.label}</strong>
                {!group.exists && <span className="badge warning">user removed</span>}
              </div>
              <table className="table compact">
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Origin</th>
                    <th>Mode</th>
                    <th>Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {group.domains.map((domain) => (
                    <tr key={domain.domain}>
                      <td>{domain.domain}</td>
                      <td>{domain.origin_ip}</td>
                      <td>
                        <span className={`badge ${domain.proxied ? 'info' : 'secondary'}`}>
                          {domain.proxied ? 'proxied' : 'direct'}
                        </span>
                      </td>
                      <td>{formatDate(domain.updated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))
        )}
      </div>

      <div className="card">
        <div className="section-header">
          <h3 className="section-title">Authoritative Nameservers</h3>
          <button className="button secondary" onClick={() => refreshNameServerStatus()} disabled={nsPending}>
            {nsPending ? 'Checking…' : 'Check reachability'}
          </button>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>Node</th>
              <th>Hostname</th>
              <th>IPv4</th>
              <th>Status</th>
              <th>Latency</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody>
            {nameservers.map((entry) => {
              const status = nsStatusMap.get(`${entry.fqdn}|${entry.ipv4}`);
              return (
                <tr key={`${entry.node_id}-${entry.ipv4}`}>
                  <td>{entry.name}</td>
                  <td>{entry.fqdn}</td>
                  <td>{entry.ipv4}</td>
                  <td>
                    {status ? (
                      <span className={`badge ${status.healthy ? 'success' : 'danger'}`}>
                        {status.healthy ? 'healthy' : 'unreachable'}
                      </span>
                    ) : (
                      <span className="badge secondary">unknown</span>
                    )}
                  </td>
                  <td>{status ? `${status.latency_ms} ms` : '—'}</td>
                  <td>{status?.message ?? '—'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {error && <div className="alert">{error}</div>}
    </div>
  );
};
