import React, { useState, useEffect } from 'react';
import { formatDistanceToNow } from 'date-fns';
import { nodes as nodesApi, infra } from '../api/client';
import { Node, NameServerEntry, NameServerStatus } from '../types';
import Input from '../components/ui/Input';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import PageHeader from '../components/PageHeader';
import toast from 'react-hot-toast';
import './AdminInfrastructure.css';

export default function AdminInfrastructure() {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [nameservers, setNameservers] = useState<NameServerEntry[]>([]);
  const [nsStatus, setNsStatus] = useState<NameServerStatus[]>([]);
  const [edges, setEdges] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [checkingHealth, setCheckingHealth] = useState(false);
  const [joinCommand, setJoinCommand] = useState('');
  const [copyingJoin, setCopyingJoin] = useState(false);
  const [nodeFormMode, setNodeFormMode] = useState<'idle' | 'create' | 'edit'>('idle');
  const [nodeForm, setNodeForm] = useState({
    name: '',
    ips: '',
    nsIps: '',
    nsLabel: '',
    nsBaseDomain: '',
    apiEndpoint: '',
  });
  const [editingNodeId, setEditingNodeId] = useState<string | null>(null);
  const [savingNode, setSavingNode] = useState(false);

  useEffect(() => {
    loadInfrastructure();
  }, []);

  const loadInfrastructure = async () => {
    try {
      const [nodesData, nsData, edgeData, statusData, joinCmd] = await Promise.all([
        nodesApi.list(),
        infra.nameservers(),
        infra.edges(),
        infra.nameserverStatus().catch(() => [] as NameServerStatus[]),
        infra.joinCommand().catch(() => ''),
      ]);
      setNodes(nodesData);
      setNameservers(nsData);
      setEdges(edgeData);
      setNsStatus(statusData || []);
      setJoinCommand(joinCmd || '');
    } catch (error) {
      toast.error('Failed to load infrastructure data');
    } finally {
      setLoading(false);
    }
  };

  const checkNameServerHealth = async () => {
    setCheckingHealth(true);
    try {
      const status = await infra.checkNameServers();
      setNsStatus(status);
      toast.success('Health check completed');
    } catch (error) {
      toast.error('Health check failed');
    } finally {
      setCheckingHealth(false);
    }
  };

  const handleCopyJoinCommand = async () => {
    if (!joinCommand) return;
    try {
      setCopyingJoin(true);
      await navigator.clipboard.writeText(joinCommand);
      toast.success('Join command copied to clipboard');
    } catch (error) {
      toast.error('Failed to copy join command');
    } finally {
      setCopyingJoin(false);
    }
  };

  const parseList = (value: string) =>
    value
      .split(/[,\n]/)
      .map((entry) => entry.trim())
      .filter(Boolean);

  const resetNodeForm = () => {
    setNodeForm({
      name: '',
      ips: '',
      nsIps: '',
      nsLabel: '',
      nsBaseDomain: '',
      apiEndpoint: '',
    });
    setEditingNodeId(null);
    setNodeFormMode('idle');
  };

  const openCreateNode = () => {
    resetNodeForm();
    setNodeFormMode('create');
  };

  const openEditNode = (node: Node) => {
    setNodeFormMode('edit');
    setEditingNodeId(node.id);
    setNodeForm({
      name: node.name,
      ips: node.ips.join(', '),
      nsIps: (node.ns_ips || []).join(', '),
      nsLabel: node.ns_label || '',
      nsBaseDomain: node.ns_base_domain || '',
      apiEndpoint: node.api_endpoint || '',
    });
  };

  const handleNodeFormChange = (field: keyof typeof nodeForm, value: string) => {
    setNodeForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleSaveNode = async (event: React.FormEvent) => {
    event.preventDefault();
    const name = nodeForm.name.trim();
    const ips = parseList(nodeForm.ips);
    if (!name) {
      toast.error('Node name is required');
      return;
    }
    if (ips.length === 0) {
      toast.error('Provide at least one IP address');
      return;
    }
    setSavingNode(true);
    try {
      if (nodeFormMode === 'create') {
        await nodesApi.create({
          name,
          ips,
          ns_ips: parseList(nodeForm.nsIps),
          ns_label: nodeForm.nsLabel.trim() || undefined,
          ns_base_domain: nodeForm.nsBaseDomain.trim() || undefined,
          api_endpoint: nodeForm.apiEndpoint.trim() || undefined,
        });
        toast.success('Node created');
      } else if (nodeFormMode === 'edit' && editingNodeId) {
        const baseNode = nodes.find((n) => n.id === editingNodeId);
        if (!baseNode) {
          toast.error('Node not found');
          setSavingNode(false);
          return;
        }
        await nodesApi.update(editingNodeId, {
          ...baseNode,
          name,
          ips,
          ns_ips: parseList(nodeForm.nsIps),
          ns_label: nodeForm.nsLabel.trim() || undefined,
          ns_base_domain: nodeForm.nsBaseDomain.trim() || undefined,
          api_endpoint: nodeForm.apiEndpoint.trim() || undefined,
        });
        toast.success('Node updated');
      }
      await loadInfrastructure();
      resetNodeForm();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to save node');
    } finally {
      setSavingNode(false);
    }
  };

  const handleDeleteNode = async (id: string) => {
    if (!confirm('Delete this node?')) return;
    try {
      await nodesApi.delete(id);
      toast.success('Node deleted');
      await loadInfrastructure();
      if (editingNodeId === id) {
        resetNodeForm();
      }
      if (selectedNode?.id === id) {
        setSelectedNode(null);
      }
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to delete node');
    }
  };

  const handleRebuild = async () => {
    if (!confirm('Rebuild all services? This will reload configurations.')) return;

    try {
      await infra.rebuild();
      toast.success('Services rebuilt successfully');
    } catch (error) {
      toast.error('Rebuild failed');
    }
  };

  const getNodeStatus = (node: Node): NonNullable<Node['status']> => {
    if (node.status) return node.status;
    if (!node.edge_ips || node.edge_ips.length === 0) return 'idle';
    return 'pending';
  };

  const getStatusColor = (status: Node['status'] | string) => {
    switch (status) {
      case 'healthy':
        return 'var(--color-success)';
      case 'degraded':
      case 'pending':
        return 'var(--color-warning)';
      case 'offline':
        return 'var(--color-danger)';
      case 'idle':
      default:
        return 'var(--color-text-tertiary)';
    }
  };

  const getStatusVariant = (status: Node['status'] | string): 'success' | 'warning' | 'danger' | 'default' => {
    switch (status) {
      case 'healthy':
        return 'success';
      case 'degraded':
      case 'pending':
        return 'warning';
      case 'offline':
        return 'danger';
      case 'idle':
      default:
        return 'default';
    }
  };

  if (loading) {
    return (
      <div className="loading-state">
        <div className="spinner-large" />
        <p>Loading infrastructure...</p>
      </div>
    );
  }

  return (
    <div className="admin-infrastructure">
      <PageHeader
        title="Infrastructure"
        subtitle="Cluster topology and node management"
      >
        <Button variant="secondary" onClick={checkNameServerHealth} loading={checkingHealth}>
          Check Health
        </Button>
        <Button variant="danger" onClick={handleRebuild}>
          Rebuild Services
        </Button>
      </PageHeader>

      <div className="infrastructure-grid">
        <Card title="Cluster Topology" className="cluster-card">
          <div className="cluster-visualization">
            <div className="cluster-center">
              <div className="cluster-hub">
                <span className="hub-label">Cluster</span>
                <span className="hub-count">{nodes.length} nodes</span>
              </div>
            </div>
            <div className="cluster-nodes">
              {nodes.map((node, index) => {
                const angle = (360 / nodes.length) * index;
                const status = getNodeStatus(node);
                const isSelected = selectedNode?.id === node.id;
                
                return (
                  <div
                    key={node.id}
                    className={`cluster-node ${isSelected ? 'selected' : ''}`}
                    style={{
                      transform: `rotate(${angle}deg) translateY(-120px) rotate(-${angle}deg)`,
                    }}
                    onClick={() => setSelectedNode(node)}
                  >
                    <div
                      className="node-dot"
                      style={{ backgroundColor: getStatusColor(status) }}
                    />
                    <span className="node-name">{node.name}</span>
                    <div className="node-services">
                      {node.ns_ips?.length > 0 && <span className="service-badge">NS</span>}
                      {node.edge_ips?.length > 0 && <span className="service-badge">Edge</span>}
                    </div>
                  </div>
                );
              })}
            </div>
            {nodes.map((node, index) => {
              const angle = (360 / nodes.length) * index;
              return (
                <svg
                  key={`line-${node.id}`}
                  className="cluster-line"
                  style={{
                    transform: `rotate(${angle}deg)`,
                  }}
                >
                  <line
                    x1="50%"
                    y1="50%"
                    x2="50%"
                    y2="25%"
                    stroke={getStatusColor(getNodeStatus(node))}
                    strokeWidth="1"
                    strokeDasharray="2 4"
                    opacity="0.3"
                  />
                </svg>
              );
            })}
          </div>
        </Card>

        <Card title="Node Details" className="node-details-card">
          {selectedNode ? (
            <div className="node-details">
              <h3>{selectedNode.name}</h3>
              <div className="detail-row">
                <span className="detail-label">Node ID:</span>
                <span className="detail-value mono">{selectedNode.id}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Status:</span>
                <div className="detail-value status-cell">
                  <Badge variant={getStatusVariant(getNodeStatus(selectedNode))} size="sm" dot>
                    {getNodeStatus(selectedNode)}
                  </Badge>
                  {selectedNode.status_message && (
                    <span className="status-message">{selectedNode.status_message}</span>
                  )}
                </div>
              </div>
              {(selectedNode.total_edges ?? 0) > 0 && (
                <div className="detail-row">
                  <span className="detail-label">Edge Health:</span>
                  <span className="detail-value mono">
                    {(selectedNode.healthy_edges ?? 0)} / {(selectedNode.total_edges ?? 0)} healthy
                  </span>
                </div>
              )}
              {selectedNode.last_health_at && (
                <div className="detail-row">
                  <span className="detail-label">Last Check:</span>
                  <span className="detail-value">
                    {formatDistanceToNow(new Date(selectedNode.last_health_at), { addSuffix: true })}
                  </span>
                </div>
              )}
              <div className="detail-row">
                <span className="detail-label">IPs:</span>
                <div className="detail-list">
                  {selectedNode.ips.map(ip => (
                    <span key={ip} className="ip-tag mono">{ip}</span>
                  ))}
                </div>
              </div>
              {selectedNode.ns_ips && selectedNode.ns_ips.length > 0 && (
                <div className="detail-row">
                  <span className="detail-label">NS IPs:</span>
                  <div className="detail-list">
                    {selectedNode.ns_ips.map(ip => (
                      <span key={ip} className="ip-tag mono">{ip}</span>
                    ))}
                  </div>
                </div>
              )}
              {selectedNode.edge_ips && selectedNode.edge_ips.length > 0 && (
                <div className="detail-row">
                  <span className="detail-label">Edge IPs:</span>
                  <div className="detail-list">
                    {selectedNode.edge_ips.map(ip => (
                      <span key={ip} className="ip-tag mono">{ip}</span>
                    ))}
                  </div>
                </div>
              )}
              {selectedNode.ns_label && (
                <div className="detail-row">
                  <span className="detail-label">NS Label:</span>
                  <span className="detail-value">{selectedNode.ns_label}</span>
                </div>
              )}
              {selectedNode.ns_base_domain && (
                <div className="detail-row">
                  <span className="detail-label">Base Domain:</span>
                  <span className="detail-value mono">{selectedNode.ns_base_domain}</span>
                </div>
              )}
              {selectedNode.api_endpoint && (
                <div className="detail-row">
                  <span className="detail-label">API Endpoint:</span>
                  <span className="detail-value mono">{selectedNode.api_endpoint}</span>
                </div>
              )}
            </div>
          ) : (
            <div className="empty-state">
              <p>Select a node to view details</p>
            </div>
          )}
        </Card>
      </div>

      <Card title="Node Management" className="node-management-card">
        <div className="node-management-header">
          <Button variant="primary" size="sm" onClick={openCreateNode}>
            Add Node
          </Button>
        </div>
        <div className="node-management-table">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Status</th>
                <th>IPs</th>
                <th>NS IPs</th>
                <th>API Endpoint</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {nodes.length === 0 ? (
                <tr>
                  <td colSpan={6} className="node-empty">No nodes configured</td>
                </tr>
              ) : (
                nodes.map((node) => (
                  <tr key={node.id} className={editingNodeId === node.id && nodeFormMode === 'edit' ? 'node-row-editing' : ''}>
                    <td>{node.name}</td>
                    <td>
                      <Badge variant={getStatusVariant(getNodeStatus(node))} size="sm" dot>
                        {getNodeStatus(node)}
                      </Badge>
                    </td>
                    <td className="mono">{node.ips.join(', ')}</td>
                    <td className="mono">{(node.ns_ips || []).join(', ') || '—'}</td>
                    <td className="mono">{node.api_endpoint || '—'}</td>
                    <td className="node-actions">
                      <Button variant="secondary" size="sm" onClick={() => openEditNode(node)}>
                        Edit
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => handleDeleteNode(node.id)}>
                        Delete
                      </Button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        {nodeFormMode !== 'idle' && (
          <form className="node-form" onSubmit={handleSaveNode}>
            <div className="node-form-grid">
              <Input
                label="Node Name"
                value={nodeForm.name}
                onChange={(e) => handleNodeFormChange('name', e.target.value)}
                required
                fullWidth
              />
              <div className="node-textarea-field">
                <label>IPs (comma or newline separated)</label>
                <textarea
                  value={nodeForm.ips}
                  onChange={(e) => handleNodeFormChange('ips', e.target.value)}
                  required
                  className="node-textarea"
                  rows={2}
                />
              </div>
              <div className="node-textarea-field">
                <label>NS IPs</label>
                <textarea
                  value={nodeForm.nsIps}
                  onChange={(e) => handleNodeFormChange('nsIps', e.target.value)}
                  className="node-textarea"
                  rows={2}
                  placeholder="Optional"
                />
              </div>
              <Input
                label="NS Label"
                value={nodeForm.nsLabel}
                onChange={(e) => handleNodeFormChange('nsLabel', e.target.value)}
                placeholder="e.g. ns"
                fullWidth
              />
              <Input
                label="NS Base Domain"
                value={nodeForm.nsBaseDomain}
                onChange={(e) => handleNodeFormChange('nsBaseDomain', e.target.value)}
                placeholder="e.g. example.net"
                fullWidth
              />
              <Input
                label="API Endpoint"
                value={nodeForm.apiEndpoint}
                onChange={(e) => handleNodeFormChange('apiEndpoint', e.target.value)}
                placeholder="https://node-api.example.com"
                fullWidth
              />
            </div>
            <div className="node-form-actions">
              <Button variant="primary" type="submit" loading={savingNode}>
                Save Node
              </Button>
              <Button variant="ghost" type="button" onClick={resetNodeForm} disabled={savingNode}>
                Cancel
              </Button>
            </div>
          </form>
        )}
      </Card>

      <Card title="Join Helper" className="join-card">
        <p className="join-description">Run this command on the new node (adjust name and IP arguments as needed).</p>
        <textarea
          className="join-command"
          rows={3}
          value={joinCommand || 'Command unavailable'}
          readOnly
        />
        <div className="join-actions">
          <Button variant="secondary" size="sm" onClick={handleCopyJoinCommand} disabled={!joinCommand} loading={copyingJoin}>
            Copy Join Command
          </Button>
        </div>
      </Card>

      <Card title="Nameservers" className="nameservers-card">
        <div className="nameservers-description">
          <p>Authoritative DNS servers for domain delegation</p>
        </div>
        <div className="nameservers-grid">
          {nameservers.map((ns) => {
            const status = nsStatus.find(s => s.node_id === ns.node_id);
            const lastChecked = status?.checked_at ? formatDistanceToNow(new Date(status.checked_at), { addSuffix: true }) : null;
            const badgeVariant: 'default' | 'success' | 'danger' = status ? (status.healthy ? 'success' : 'danger') : 'default';
            const badgeLabel = status ? (status.healthy ? 'Healthy' : 'Unhealthy') : 'Unknown';
            const badgeTitle = status?.message || (lastChecked ? `Last checked ${lastChecked}` : undefined);
            return (
              <div key={ns.node_id} className="nameserver-item">
                <div className="ns-node">{ns.name}</div>
                <div className="ns-content">
                  <div className="ns-fqdn mono">{ns.fqdn}</div>
                  <div className="ns-ip mono">{ns.ipv4}</div>
                </div>
                <div className="ns-status">
                  <Badge
                    variant={badgeVariant}
                    size="sm"
                    dot
                    title={badgeTitle}
                  >
                    {badgeLabel}
                  </Badge>
                  {status?.message && (
                    <span className="ns-message">{status.message}</span>
                  )}
                  {lastChecked && (
                    <span className="ns-last-checked">Checked {lastChecked}</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      <Card title="Edge IP Addresses" className="edges-card">
        <div className="edge-ips-info">
          <p className="edge-description">Public anycast IPs distributed across cluster nodes for receiving client traffic</p>
        </div>
        <div className="edges-grid">
          {edges.map((edge, index) => {
            // Simulate IP distribution across nodes (in real app this would come from backend)
            const nodeId = (index % 4) + 1;
            return (
              <div key={edge} className="edge-item">
                <div className="edge-node-indicator">node-{nodeId}</div>
                <div className="edge-content">
                  <span className="edge-ip mono">{edge}</span>
                  <Badge variant="success" size="sm">Active</Badge>
                </div>
              </div>
            );
          })}
          {edges.length === 0 && (
            <div className="empty-state">
              <p>No edge IPs configured</p>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}
