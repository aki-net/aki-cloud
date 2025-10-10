import React, { useState, useEffect, useRef } from 'react';
import { domains as domainsApi, infra } from '../api/client';
import { Domain, CreateDomainPayload, NameServerEntry } from '../types';
import Table from '../components/ui/Table';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import Switch from '../components/ui/Switch';
import Badge from '../components/ui/Badge';
import Card from '../components/ui/Card';
import toast from 'react-hot-toast';
import { format } from 'date-fns';
import './UserDashboard.css';

export default function UserDashboard() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [nameservers, setNameservers] = useState<NameServerEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDomains, setSelectedDomains] = useState<Set<string>>(new Set());
  const [showAddDomain, setShowAddDomain] = useState(false);
  const [editingDomain, setEditingDomain] = useState<string | null>(null);
  const [editingIP, setEditingIP] = useState('');
  const editInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [domainData, nsData] = await Promise.all([
        domainsApi.list(),
        infra.nameservers(),
      ]);
      setDomains(domainData);
      setNameservers(nsData);
    } catch (error) {
      toast.error('Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const handleToggleProxy = async (domain: Domain) => {
    try {
      const updated = await domainsApi.update(domain.domain, {
        origin_ip: domain.origin_ip,
        proxied: !domain.proxied,
        ttl: domain.ttl,
      });
      setDomains(domains.map(d => d.domain === domain.domain ? updated : d));
      toast.success(`Proxy ${!domain.proxied ? 'enabled' : 'disabled'} for ${domain.domain}`);
    } catch (error) {
      toast.error('Failed to update proxy setting');
    }
  };

  const handleEditIP = (domain: Domain) => {
    setEditingDomain(domain.domain);
    setEditingIP(domain.origin_ip);
    setTimeout(() => editInputRef.current?.select(), 0);
  };

  const handleSaveIP = async (domain: Domain) => {
    if (!editingIP || editingIP === domain.origin_ip) {
      setEditingDomain(null);
      return;
    }

    try {
      const updated = await domainsApi.update(domain.domain, {
        origin_ip: editingIP,
        proxied: domain.proxied,
        ttl: domain.ttl,
      });
      setDomains(domains.map(d => d.domain === domain.domain ? updated : d));
      toast.success(`Updated IP for ${domain.domain}`);
    } catch (error) {
      toast.error('Failed to update IP address');
    } finally {
      setEditingDomain(null);
    }
  };

  const handleDeleteSelected = async () => {
    if (selectedDomains.size === 0) return;

    if (!confirm(`Delete ${selectedDomains.size} domain(s)?`)) return;

    try {
      await Promise.all(Array.from(selectedDomains).map(d => domainsApi.delete(d)));
      setDomains(domains.filter(d => !selectedDomains.has(d.domain)));
      setSelectedDomains(new Set());
      toast.success(`Deleted ${selectedDomains.size} domain(s)`);
    } catch (error) {
      toast.error('Failed to delete domains');
    }
  };

  const filteredDomains = domains.filter(d =>
    d.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
    d.origin_ip.includes(searchQuery)
  );

  const getTLSBadge = (domain: Domain) => {
    const statusMap = {
      none: { variant: 'default' as const, label: 'No TLS' },
      pending: { variant: 'warning' as const, label: 'Pending' },
      active: { variant: 'success' as const, label: 'Active' },
      errored: { variant: 'danger' as const, label: 'Error' },
      awaiting_dns: { variant: 'info' as const, label: 'Awaiting DNS' },
    };
    const status = statusMap[domain.tls.status] || statusMap.none;
    return <Badge variant={status.variant} size="sm">{status.label}</Badge>;
  };

  const columns = [
    {
      key: 'domain',
      header: 'Domain',
      accessor: (d: Domain) => (
        <div className="domain-name">
          <span className="mono">{d.domain}</span>
        </div>
      ),
    },
    {
      key: 'origin_ip',
      header: 'Origin IP',
      accessor: (d: Domain) => (
        <div className="domain-ip">
          {editingDomain === d.domain ? (
            <input
              ref={editInputRef}
              className="ip-edit-input"
              value={editingIP}
              onChange={(e) => setEditingIP(e.target.value)}
              onBlur={() => handleSaveIP(d)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleSaveIP(d);
                if (e.key === 'Escape') setEditingDomain(null);
              }}
            />
          ) : (
            <span className="ip-display mono" onClick={() => handleEditIP(d)}>
              {d.origin_ip}
              <svg className="edit-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7" />
                <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z" />
              </svg>
            </span>
          )}
        </div>
      ),
    },
    {
      key: 'proxied',
      header: 'Proxy',
      accessor: (d: Domain) => (
        <Switch
          checked={d.proxied}
          onChange={() => handleToggleProxy(d)}
          size="sm"
        />
      ),
      width: '100px',
      align: 'center' as const,
    },
    {
      key: 'tls',
      header: 'TLS',
      accessor: (d: Domain) => getTLSBadge(d),
      width: '120px',
    },
    {
      key: 'ttl',
      header: 'TTL',
      accessor: (d: Domain) => <span className="mono">{d.ttl}s</span>,
      width: '80px',
      align: 'right' as const,
    },
    {
      key: 'updated',
      header: 'Updated',
      accessor: (d: Domain) => (
        <span className="text-secondary">
          {format(new Date(d.updated_at), 'MMM d, HH:mm')}
        </span>
      ),
      width: '140px',
    },
  ];

  return (
    <div className="user-dashboard">
      <div className="dashboard-header">
        <div className="header-left">
          <h1 className="dashboard-title">Your Domains</h1>
          <p className="dashboard-subtitle">{domains.length} domains registered</p>
        </div>
        <div className="header-actions">
          <Input
            placeholder="Search domains or IPs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            icon={
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" />
                <path d="M21 21l-4.35-4.35" />
              </svg>
            }
          />
          {selectedDomains.size > 0 && (
            <Button variant="danger" onClick={handleDeleteSelected}>
              Delete {selectedDomains.size} selected
            </Button>
          )}
          <Button variant="primary" onClick={() => setShowAddDomain(true)}>
            Add Domain
          </Button>
        </div>
      </div>

      <Card className="domains-card" padding="none">
        <Table
          columns={columns}
          data={filteredDomains}
          keyExtractor={(d) => d.domain}
          selectedRows={selectedDomains}
          onRowSelect={(id, selected) => {
            const newSelected = new Set(selectedDomains);
            if (selected) {
              newSelected.add(id);
            } else {
              newSelected.delete(id);
            }
            setSelectedDomains(newSelected);
          }}
          onSelectAll={(selected) => {
            if (selected) {
              setSelectedDomains(new Set(filteredDomains.map(d => d.domain)));
            } else {
              setSelectedDomains(new Set());
            }
          }}
          loading={loading}
          emptyMessage="No domains found"
        />
      </Card>

      {nameservers.length > 0 && (
        <Card className="nameservers-card" title="Nameservers">
          <div className="nameservers-list">
            {nameservers.map((ns) => (
              <div key={ns.node_id} className="nameserver-item">
                <span className="ns-fqdn mono">{ns.fqdn}</span>
                <span className="ns-ip mono">{ns.ipv4}</span>
              </div>
            ))}
          </div>
          <p className="ns-hint">Configure these nameservers at your domain registrar</p>
        </Card>
      )}

      {showAddDomain && <AddDomainModal onClose={() => setShowAddDomain(false)} onAdd={loadData} />}
    </div>
  );
}

function AddDomainModal({ onClose, onAdd }: { onClose: () => void; onAdd: () => void }) {
  const [formData, setFormData] = useState<CreateDomainPayload>({
    domain: '',
    origin_ip: '',
    proxied: true,
    ttl: 60,
  });
  const [bulkMode, setBulkMode] = useState(false);
  const [bulkDomains, setBulkDomains] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      if (bulkMode) {
        const domainList = bulkDomains.split('\n').map(d => d.trim()).filter(Boolean);
        await domainsApi.bulkCreate({
          domains: domainList,
          origin_ip: formData.origin_ip,
          proxied: formData.proxied,
          ttl: formData.ttl,
        });
        toast.success(`Added ${domainList.length} domains`);
      } else {
        await domainsApi.create(formData);
        toast.success(`Added ${formData.domain}`);
      }
      onAdd();
      onClose();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to add domain');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Add Domain</h2>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>
        <form onSubmit={handleSubmit} className="modal-body">
          <div className="form-tabs">
            <button
              type="button"
              className={`tab ${!bulkMode ? 'tab-active' : ''}`}
              onClick={() => setBulkMode(false)}
            >
              Single Domain
            </button>
            <button
              type="button"
              className={`tab ${bulkMode ? 'tab-active' : ''}`}
              onClick={() => setBulkMode(true)}
            >
              Bulk Import
            </button>
          </div>

          {bulkMode ? (
            <div className="form-group">
              <label>Domains (one per line)</label>
              <textarea
                className="bulk-textarea"
                rows={6}
                placeholder="example.com&#10;app.example.com&#10;api.example.com"
                value={bulkDomains}
                onChange={(e) => setBulkDomains(e.target.value)}
                required
              />
            </div>
          ) : (
            <Input
              label="Domain"
              placeholder="example.com"
              value={formData.domain}
              onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
              fullWidth
              required
            />
          )}

          <Input
            label="Origin IP"
            placeholder="192.168.1.1"
            value={formData.origin_ip}
            onChange={(e) => setFormData({ ...formData, origin_ip: e.target.value })}
            fullWidth
            required
          />

          <div className="form-row">
            <Input
              type="number"
              label="TTL (seconds)"
              value={formData.ttl}
              onChange={(e) => setFormData({ ...formData, ttl: parseInt(e.target.value) || 60 })}
              fullWidth
            />
            <div className="form-group">
              <label>Proxy</label>
              <Switch
                checked={formData.proxied}
                onChange={(checked) => setFormData({ ...formData, proxied: checked })}
                label={formData.proxied ? 'Enabled' : 'Disabled'}
              />
            </div>
          </div>

          <div className="modal-actions">
            <Button variant="ghost" onClick={onClose} disabled={loading}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={loading}>
              Add {bulkMode ? 'Domains' : 'Domain'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
