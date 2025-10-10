import React, { useState, useEffect } from 'react';
import { nodes as nodesApi, infra } from '../api/client';
import { Node, NameServerEntry, NameServerStatus } from '../types';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
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

  useEffect(() => {
    loadInfrastructure();
  }, []);

  const loadInfrastructure = async () => {
    try {
      const [nodesData, nsData, edgeData] = await Promise.all([
        nodesApi.list(),
        infra.nameservers(),
        infra.edges(),
      ]);
      setNodes(nodesData);
      setNameservers(nsData);
      setEdges(edgeData);
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

  const handleRebuild = async () => {
    if (!confirm('Rebuild all services? This will reload configurations.')) return;

    try {
      await infra.rebuild();
      toast.success('Services rebuilt successfully');
    } catch (error) {
      toast.error('Rebuild failed');
    }
  };

  const getNodeStatus = (node: Node) => {
    // Mock status based on node data
    const hasNS = node.ns_ips && node.ns_ips.length > 0;
    const hasEdge = node.edge_ips && node.edge_ips.length > 0;
    
    if (hasNS && hasEdge) return 'healthy';
    if (hasNS || hasEdge) return 'partial';
    return 'offline';
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'var(--color-success)';
      case 'partial': return 'var(--color-warning)';
      case 'offline': return 'var(--color-danger)';
      default: return 'var(--color-text-tertiary)';
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
      <div className="page-header">
        <div className="header-content">
          <h1>Infrastructure</h1>
          <p className="subtitle">Cluster topology and node management</p>
        </div>
        <div className="header-actions">
          <Button variant="secondary" onClick={checkNameServerHealth} loading={checkingHealth}>
            Check Health
          </Button>
          <Button variant="danger" onClick={handleRebuild}>
            Rebuild Services
          </Button>
        </div>
      </div>

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

      <Card title="Nameservers" className="nameservers-card">
        <div className="nameservers-grid">
          {nameservers.map((ns) => {
            const status = nsStatus.find(s => s.node_id === ns.node_id);
            return (
              <div key={ns.node_id} className="nameserver-item">
                <div className="ns-header">
                  <span className="ns-name">{ns.name}</span>
                  <Badge
                    variant={status?.healthy ? 'success' : status ? 'danger' : 'default'}
                    size="sm"
                    dot
                  >
                    {status?.healthy ? 'Healthy' : status ? 'Unhealthy' : 'Unknown'}
                  </Badge>
                </div>
                <div className="ns-details">
                  <span className="ns-fqdn mono">{ns.fqdn}</span>
                  <span className="ns-ip mono">{ns.ipv4}</span>
                  {status && (
                    <span className="ns-latency">
                      {status.latency_ms}ms
                    </span>
                  )}
                </div>
                {status?.message && (
                  <div className="ns-message">{status.message}</div>
                )}
              </div>
            );
          })}
        </div>
      </Card>

      <Card title="Edge Servers" className="edges-card">
        <div className="edges-grid">
          {edges.map((edge) => (
            <div key={edge} className="edge-item">
              <div className="edge-icon">🌍</div>
              <span className="edge-ip mono">{edge}</span>
              <Badge variant="success" size="sm">Active</Badge>
            </div>
          ))}
          {edges.length === 0 && (
            <div className="empty-state">
              <p>No edge servers configured</p>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}
