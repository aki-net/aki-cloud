import React, { useState, useEffect, useRef } from 'react';
import { domains as domainsApi, infra, admin } from '../api/client';
import { Domain, CreateDomainPayload, NameServerEntry, DomainOverview } from '../types';
import Table from './ui/Table';
import Button from './ui/Button';
import Input from './ui/Input';
import Switch from './ui/Switch';
import Badge from './ui/Badge';
import Card from './ui/Card';
import PageHeader from './PageHeader';
import toast from 'react-hot-toast';
import { format, formatDistanceToNow } from 'date-fns';
import { useAuth } from '../contexts/AuthContext';
import './DomainManagement.css';

interface Props {
  isAdmin?: boolean;
}

export default function DomainManagement({ isAdmin = false }: Props) {
  const { user } = useAuth();
  const [domains, setDomains] = useState<Domain[]>([]);
  const [allDomains, setAllDomains] = useState<DomainOverview[]>([]);
  const [nameservers, setNameservers] = useState<NameServerEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDomains, setSelectedDomains] = useState<Set<string>>(new Set());
  const [showAddDomain, setShowAddDomain] = useState(false);
  const [editingDomain, setEditingDomain] = useState<string | null>(null);
  const [editingIP, setEditingIP] = useState('');
  const [viewMode, setViewMode] = useState<'my' | 'all' | 'orphaned'>('my');
  const [bulkIP, setBulkIP] = useState('');
  const [bulkOwner, setBulkOwner] = useState('');
  const editInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const promises: Promise<any>[] = [
        domainsApi.list(),
        infra.nameservers(),
      ];
      
      if (isAdmin) {
        promises.push(admin.domainsOverview().catch(() => []));
      }
      
      const [domainData, nsData, overviewData] = await Promise.all(promises);
      
      setDomains(domainData);
      setNameservers(nsData);
      if (isAdmin && overviewData) {
        setAllDomains(overviewData);
      }
    } catch (error) {
      toast.error('Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const modeLabel = (mode?: string | null) => {
    if (!mode) return '';
    switch (mode) {
      case 'flexible':
        return 'Flexible';
      case 'full':
        return 'Full';
      case 'full_strict':
        return 'Full (Strict)';
      case 'strict_origin_pull':
        return 'Strict Origin Pull';
      case 'off':
        return 'Off';
      default:
        return mode;
    }
  };

  const computeRetryHint = (iso?: string | null) => {
    if (!iso) return '';
    const retry = new Date(iso);
    if (
      Number.isNaN(retry.getTime()) ||
      retry.getUTCFullYear() <= 1900
    ) {
      return '';
    }
    const now = Date.now();
    if (retry.getTime() <= now) {
      return 'Retrying now';
    }
    return `Retry ${formatDistanceToNow(retry, { addSuffix: true })}`;
  };

  const handleToggleProxy = async (domain: Domain | DomainOverview) => {
    try {
      const domainName = 'domain' in domain ? domain.domain : domain.domain;
      const newProxied = !domain.proxied;
      
      // If disabling proxy, also disable TLS
      const tlsPayload = !newProxied ? { mode: 'off' as const, use_recommended: false } : undefined;
      
      const updated = await domainsApi.update(domainName, {
        origin_ip: domain.origin_ip,
        proxied: newProxied,
        ttl: 'ttl' in domain ? domain.ttl : 60,
        tls: tlsPayload,
      });
      
      if (viewMode === 'my') {
        setDomains(domains.map(d => d.domain === domainName ? updated : d));
      }
      loadData();
      toast.success(`Proxy ${newProxied ? 'enabled' : 'disabled'} for ${domainName}`);
    } catch (error) {
      toast.error('Failed to update proxy setting');
    }
  };

  const handleChangeTLS = async (domain: Domain | DomainOverview, mode: string) => {
    try {
      const domainName = 'domain' in domain ? domain.domain : domain.domain;
      
      if (!domain.proxied && mode !== 'off') {
        toast.error('Enable proxy first to use TLS');
        return;
      }
      
      let newMode: any;
      let useRecommended = false;
      
      if (mode === 'auto') {
        newMode = 'flexible';
        useRecommended = true;
      } else {
        newMode = mode;
      }
      
      const updated = await domainsApi.update(domainName, {
        origin_ip: domain.origin_ip,
        proxied: domain.proxied,
        ttl: 'ttl' in domain ? domain.ttl : 60,
        tls: {
          mode: newMode,
          use_recommended: useRecommended,
        },
      });
      
      if (viewMode === 'my') {
        setDomains(domains.map(d => d.domain === domainName ? updated : d));
      }
      loadData();
      toast.success(`TLS mode updated for ${domainName}`);
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to update TLS setting');
    }
  };

  const handleEditIP = (domain: Domain | DomainOverview) => {
    const domainName = 'domain' in domain ? domain.domain : domain.domain;
    setEditingDomain(domainName);
    setEditingIP(domain.origin_ip);
    setTimeout(() => editInputRef.current?.select(), 0);
  };

  const handleSaveIP = async (domain: Domain | DomainOverview) => {
    const domainName = 'domain' in domain ? domain.domain : domain.domain;
    
    if (!editingIP || editingIP === domain.origin_ip) {
      setEditingDomain(null);
      return;
    }

    try {
      const updated = await domainsApi.update(domainName, {
        origin_ip: editingIP,
        proxied: domain.proxied,
        ttl: 'ttl' in domain ? domain.ttl : 60,
      });
      
      if (viewMode === 'my') {
        setDomains(domains.map(d => d.domain === domainName ? updated : d));
      }
      loadData();
      toast.success(`Updated IP for ${domainName}`);
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
      loadData();
      toast.success(`Deleted ${selectedDomains.size} domain(s)`);
    } catch (error) {
      toast.error('Failed to delete domains');
    }
  };

  const handleBulkProxyToggle = async (enable: boolean) => {
    if (selectedDomains.size === 0) return;

    try {
      const payload: any = { 
        domains: Array.from(selectedDomains),
        proxied: enable,
      };
      
      // If disabling proxy, also disable TLS
      if (!enable) {
        payload.tls = { mode: 'off', use_recommended: false };
      }
      
      const response = await domainsApi.bulkUpdate(payload);
      toast.success(`Updated ${response.success} domain(s)`);
      
      if (response.failed > 0) {
        toast.error(`Failed to update ${response.failed} domain(s)`);
      }
      
      loadData();
      setSelectedDomains(new Set());
    } catch (error) {
      toast.error('Failed to update domains');
    }
  };

  const handleBulkTLSUpdate = async (mode: string) => {
    if (selectedDomains.size === 0) return;

    try {
      const response = await domainsApi.bulkUpdate({
        domains: Array.from(selectedDomains),
        tls: {
          mode: mode === 'auto' ? 'flexible' : mode as any,
          use_recommended: mode === 'auto',
        },
      });
      toast.success(`Updated TLS for ${response.success} domain(s)`);
      
      if (response.failed > 0) {
        toast.error(`Failed to update ${response.failed} domain(s)`);
      }
      
      loadData();
      setSelectedDomains(new Set());
    } catch (error) {
      toast.error('Failed to update TLS settings');
    }
  };

  const handleBulkIPUpdate = async () => {
    if (selectedDomains.size === 0) return;
    const ip = bulkIP.trim();
    if (!ip) {
      toast.error('Enter a new origin IP address');
      return;
    }
    try {
      const response = await domainsApi.bulkUpdate({
        domains: Array.from(selectedDomains),
        origin_ip: ip,
      });
      toast.success(`Updated IP for ${response.success} domain(s)`);
      if (response.failed > 0) {
        toast.error(`Failed to update ${response.failed} domain(s)`);
      }
      setBulkIP('');
      setSelectedDomains(new Set());
      loadData();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to update origin IP');
    }
  };

  const handleBulkOwnerUpdate = async () => {
    if (selectedDomains.size === 0) return;
    const owner = bulkOwner.trim();
    if (!owner) {
      toast.error('Enter a new owner (email or ID)');
      return;
    }
    try {
      const response = await domainsApi.bulkUpdate({
        domains: Array.from(selectedDomains),
        owner,
      });
      toast.success(`Updated owner for ${response.success} domain(s)`);
      if (response.failed > 0) {
        toast.error(`Failed to update ${response.failed} domain(s)`);
      }
      setBulkOwner('');
      setSelectedDomains(new Set());
      loadData();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to update domain owner');
    }
  };

  const getTLSDisplay = (domain: Domain | DomainOverview) => {
    const isFullDomain = 'tls' in domain;
    
    if (!isFullDomain) {
      // DomainOverview - limited TLS info
      const statusMap = {
        none: { variant: 'default' as const, label: 'None' },
        pending: { variant: 'warning' as const, label: 'Issuing...' },
        active: { variant: 'success' as const, label: 'Active' },
        errored: { variant: 'danger' as const, label: 'Error' },
        awaiting_dns: { variant: 'info' as const, label: 'Awaiting DNS' },
      };
      
      const status = domain.tls_status ? statusMap[domain.tls_status as keyof typeof statusMap] : statusMap.none;
      const currentValue = domain.tls_use_recommended ? 'auto' : (domain.tls_mode || 'off');
      const retryHint = computeRetryHint(domain.tls_retry_after);
      
      // Admin can edit all domains
      const canEdit = isAdmin || domains.some(d => d.domain === domain.domain);
      
      return (
        <div className="tls-display">
          <select
            className="tls-mode-select"
            value={currentValue}
            onChange={(e) => canEdit && handleChangeTLS(domain, e.target.value)}
            disabled={!domain.proxied || !canEdit}
          >
            <option value="off">Off</option>
            <option value="flexible">Flexible</option>
            <option value="full">Full</option>
            <option value="full_strict">Full Strict</option>
            <option value="auto">Auto</option>
          </select>
          {domain.tls_use_recommended && (
            <span className="tls-auto-hint">
              Auto → {domain.tls_recommended_mode ? modeLabel(domain.tls_recommended_mode) : 'detecting…'}
            </span>
          )}
          {/* Always show error status, show other statuses only when proxy is on and TLS is not off */}
          {status && status.label !== 'None' && (
            (domain.tls_status === 'errored' || (domain.proxied && currentValue !== 'off')) && (
              <Badge 
                variant={status.variant} 
                size="sm" 
                title={domain.tls_last_error || ''}
              >
                {status.label}
              </Badge>
            )
          )}
          {retryHint && (
            <span className="tls-retry-hint">{retryHint}</span>
          )}
          {/* Show error icon for errored status */}
          {domain.tls_status === 'errored' && domain.tls_last_error && (
            <div className="tls-error-tooltip" title={domain.tls_last_error}>
              ⚠️
            </div>
          )}
        </div>
      );
    }
    
    // Full Domain with complete TLS data
    const statusMap = {
      none: { variant: 'default' as const, label: 'None' },
      pending: { variant: 'warning' as const, label: 'Issuing...' },
      active: { variant: 'success' as const, label: 'Active' },
      errored: { variant: 'danger' as const, label: 'Error' },
      awaiting_dns: { variant: 'info' as const, label: 'Awaiting DNS' },
    };
    
    const status = statusMap[domain.tls.status] || statusMap.none;
    const currentValue = domain.tls.use_recommended ? 'auto' : domain.tls.mode;
    const retryHint = computeRetryHint(domain.tls.retry_after);
    
    return (
      <div className="tls-display">
        <select
          className="tls-mode-select"
          value={currentValue}
          onChange={(e) => handleChangeTLS(domain, e.target.value)}
          disabled={!domain.proxied}
        >
          <option value="off">Off</option>
          <option value="flexible">Flexible</option>
          <option value="full">Full</option>
          <option value="full_strict">Full Strict</option>
          <option value="auto">Auto</option>
        </select>
        {domain.tls.use_recommended && (
          <span className="tls-auto-hint">
            Auto → {domain.tls.recommended_mode ? modeLabel(domain.tls.recommended_mode) : 'detecting…'}
          </span>
        )}
        {/* Always show error status, show other statuses only when proxy is on and TLS is not off */}
        {domain.tls.status !== 'none' && (
          (domain.tls.status === 'errored' || (domain.proxied && currentValue !== 'off')) && (
            <Badge 
              variant={status.variant} 
              size="sm" 
              title={domain.tls.last_error || ''}
            >
              {status.label}
            </Badge>
          )
        )}
        {retryHint && (
          <span className="tls-retry-hint">
            {retryHint}
          </span>
        )}
        {/* Show error icon for errored status */}
        {domain.tls.status === 'errored' && domain.tls.last_error && (
          <div className="tls-error-tooltip" title={domain.tls.last_error}>
            ⚠️
          </div>
        )}
      </div>
    );
  };

  const getFilteredData = () => {
    const query = searchQuery.toLowerCase();
    
    if (viewMode === 'my') {
      return domains.filter(d =>
        d.domain.toLowerCase().includes(query) ||
        d.origin_ip.includes(searchQuery)
      );
    }
    
    if (viewMode === 'orphaned') {
      return allDomains.filter(d => 
        !d.owner_exists &&
        (d.domain.toLowerCase().includes(query) ||
         d.origin_ip.includes(searchQuery) ||
         d.owner_email?.toLowerCase().includes(query))
      );
    }
    
    // All domains mode - search by domain, IP, or email
    return allDomains.filter(d =>
      d.domain.toLowerCase().includes(query) ||
      d.owner_email?.toLowerCase().includes(query) ||
      d.origin_ip.includes(searchQuery)
    );
  };

  const filteredData = getFilteredData();
  const orphanedCount = allDomains.filter(d => !d.owner_exists).length;
  const selectionEnabled = viewMode === 'my' || (isAdmin && (viewMode === 'all' || viewMode === 'orphaned'));

  // Build unified columns array
  const columns: any[] = [];
  
  // Domain column - always present
  columns.push({
    key: 'domain',
    header: 'Domain',
    accessor: (d: any) => (
      <div className="domain-cell">
        <span className="domain-name mono">{d.domain}</span>
        {d.owner_exists === false && <Badge variant="warning" size="sm">Orphaned</Badge>}
      </div>
    ),
  });
  
  // Owner column - only for admin in all/orphaned mode
  if (isAdmin && viewMode !== 'my') {
    columns.push({
      key: 'owner',
      header: 'Owner',
      accessor: (d: any) => (
        <div className="owner-cell">
          {d.owner_email ? (
            <span className="owner-email">{d.owner_email}</span>
          ) : (
            <span className="owner-missing">No owner</span>
          )}
        </div>
      ),
      width: '180px',
    });
  }
  
  // Origin IP column - always present
  columns.push({
    key: 'origin_ip',
    header: 'Origin IP',
    accessor: (d: any) => (
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
  });
  
  // Proxy column - always present
  columns.push({
    key: 'proxied',
    header: 'Proxy',
    accessor: (d: any) => (
      <Switch
        checked={d.proxied}
        onChange={() => handleToggleProxy(d)}
        size="sm"
      />
    ),
    width: '100px',
    align: 'center' as const,
  });
  
  // TLS column - always present
  columns.push({
    key: 'tls',
    header: 'TLS',
    accessor: (d: any) => getTLSDisplay(d),
    width: '200px',
  });
  
  // TTL column - always present
  columns.push({
    key: 'ttl',
    header: 'TTL',
    accessor: (d: any) => <span className="mono">{d.ttl || 300}s</span>,
    width: '80px',
    align: 'right' as const,
  });
  
  // Updated column - always present
  columns.push({
    key: 'updated',
    header: 'Updated',
    accessor: (d: any) => (
      <span className="text-secondary">
        {format(new Date(d.updated_at), 'MMM d, HH:mm')}
      </span>
    ),
    width: '140px',
  });

  return (
    <div className="domain-management">
      <PageHeader
        title={isAdmin ? 'Domain Management' : 'Your Domains'}
        subtitle={
          viewMode === 'my' ? `${domains.length} domains registered` :
          viewMode === 'orphaned' ? `${orphanedCount} orphaned domains` :
          `${allDomains.length} total domains`
        }
        searchPlaceholder={isAdmin && viewMode !== 'my' ? "Search domains, IPs or users..." : "Search domains or IPs..."}
        searchValue={searchQuery}
        onSearchChange={setSearchQuery}
      >
        {selectedDomains.size > 0 && selectionEnabled && (
          <>
            <div className="batch-actions">
              <div className="batch-toggle-group">
                <Button variant="secondary" size="sm" onClick={() => handleBulkProxyToggle(true)}>
                  Enable Proxy
                </Button>
                <Button variant="secondary" size="sm" onClick={() => handleBulkProxyToggle(false)}>
                  Disable Proxy
                </Button>
                <select 
                  className="batch-tls-select"
                  onChange={(e) => e.target.value && handleBulkTLSUpdate(e.target.value)}
                  defaultValue=""
                >
                  <option value="" disabled>TLS Mode...</option>
                  <option value="off">TLS Off</option>
                  <option value="flexible">Flexible</option>
                  <option value="full">Full</option>
                  <option value="full_strict">Full Strict</option>
                  <option value="auto">Auto</option>
                </select>
              </div>
              <div className="batch-input-group">
                <input
                  className="batch-input"
                  placeholder="New origin IP"
                  value={bulkIP}
                  onChange={(e) => setBulkIP(e.target.value)}
                />
                <Button variant="secondary" size="sm" onClick={handleBulkIPUpdate} disabled={!bulkIP.trim()}>
                  Update IP
                </Button>
              </div>
              {isAdmin && (
                <div className="batch-input-group">
                  <input
                    className="batch-input"
                    placeholder="Owner email or ID"
                    value={bulkOwner}
                    onChange={(e) => setBulkOwner(e.target.value)}
                  />
                  <Button variant="secondary" size="sm" onClick={handleBulkOwnerUpdate} disabled={!bulkOwner.trim()}>
                    Update Owner
                  </Button>
                </div>
              )}
            </div>
            <Button variant="danger" onClick={handleDeleteSelected}>
              Delete {selectedDomains.size}
            </Button>
          </>
        )}
        <Button variant="primary" onClick={() => setShowAddDomain(true)}>
          Add Domain
        </Button>
      </PageHeader>

      {isAdmin && (
        <div className="filter-tabs">
          <button
            className={`filter-tab ${viewMode === 'my' ? 'active' : ''}`}
            onClick={() => { setViewMode('my'); setSelectedDomains(new Set()); }}
          >
            My Domains
            <span className="tab-count">{domains.length}</span>
          </button>
          <button
            className={`filter-tab ${viewMode === 'all' ? 'active' : ''}`}
            onClick={() => { setViewMode('all'); setSelectedDomains(new Set()); }}
          >
            All Domains
            <span className="tab-count">{allDomains.length}</span>
          </button>
          <button
            className={`filter-tab ${viewMode === 'orphaned' ? 'active' : ''}`}
            onClick={() => { setViewMode('orphaned'); setSelectedDomains(new Set()); }}
          >
            Orphaned
            <span className="tab-count">{orphanedCount}</span>
          </button>
        </div>
      )}

      <Card className="domains-card" padding="none">
        <Table
          columns={columns}
          data={filteredData as any}
          keyExtractor={(d: any) => d.domain}
          selectedRows={selectionEnabled ? selectedDomains : undefined}
          onRowSelect={selectionEnabled ? (id, selected) => {
            const newSelected = new Set(selectedDomains);
            if (selected) {
              newSelected.add(id);
            } else {
              newSelected.delete(id);
            }
            setSelectedDomains(newSelected);
          } : undefined}
          onSelectAll={selectionEnabled ? (selected) => {
            if (selected) {
              setSelectedDomains(new Set(filteredData.map((d: any) => d.domain)));
            } else {
              setSelectedDomains(new Set());
            }
          } : undefined}
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
    tls: {
      mode: 'flexible',
      use_recommended: true,
    },
  });
  const [bulkMode, setBulkMode] = useState(false);
  const [bulkDomains, setBulkDomains] = useState('');
  const [loading, setLoading] = useState(false);
  const modalRef = useRef<HTMLDivElement>(null);
  const [isMouseDown, setIsMouseDown] = useState(false);

  const handleMouseDown = (e: React.MouseEvent) => {
    if (!modalRef.current?.contains(e.target as Node)) {
      setIsMouseDown(true);
    }
  };

  const handleMouseUp = (e: React.MouseEvent) => {
    if (isMouseDown && !modalRef.current?.contains(e.target as Node)) {
      onClose();
    }
    setIsMouseDown(false);
  };

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
          tls: formData.tls,
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
    <div className="modal-overlay" onMouseDown={handleMouseDown} onMouseUp={handleMouseUp}>
      <div className="modal" ref={modalRef}>
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
                onChange={(checked) => {
                  const newFormData = { ...formData, proxied: checked };
                  // If disabling proxy, also disable TLS
                  if (!checked) {
                    newFormData.tls = { mode: 'off', use_recommended: false };
                  } else if (formData.tls?.mode === 'off') {
                    // Re-enable TLS when enabling proxy
                    newFormData.tls = { mode: 'flexible', use_recommended: true };
                  }
                  setFormData(newFormData);
                }}
                label={formData.proxied ? 'Enabled' : 'Disabled'}
              />
            </div>
          </div>

          {formData.proxied && (
            <div className="form-group">
              <label>TLS Mode</label>
              <div className="tls-mode-select-wrapper">
                <select
                  className="form-select"
                  value={formData.tls?.use_recommended ? 'auto' : formData.tls?.mode || 'off'}
                  onChange={(e) => {
                    const value = e.target.value;
                    if (value === 'auto') {
                      setFormData({
                        ...formData,
                        tls: { mode: 'flexible', use_recommended: true },
                      });
                    } else {
                      setFormData({
                        ...formData,
                        tls: { mode: value as any, use_recommended: false },
                      });
                    }
                  }}
                >
                  <option value="auto">Auto (Recommended)</option>
                  <option value="off">Off</option>
                  <option value="flexible">Flexible</option>
                  <option value="full">Full</option>
                  <option value="full_strict">Full (Strict)</option>
                </select>
                <p className="tls-hint">Auto mode will detect the best TLS configuration for your origin</p>
              </div>
            </div>
          )}

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
