import React, { useState, useEffect } from 'react';
import { admin, domains as domainsApi, users } from '../api/client';
import { DomainOverview, User } from '../types';
import Table from '../components/ui/Table';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import Badge from '../components/ui/Badge';
import Card from '../components/ui/Card';
import toast from 'react-hot-toast';
import { format } from 'date-fns';
import './AdminDomains.css';

export default function AdminDomains() {
  const [domains, setDomains] = useState<DomainOverview[]>([]);
  const [usersList, setUsersList] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'orphaned' | 'expiring'>('all');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [domainData, userData] = await Promise.all([
        admin.domainsOverview(),
        users.list(),
      ]);
      setDomains(domainData);
      setUsersList(userData);
    } catch (error) {
      toast.error('Failed to load domains');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteDomain = async (domain: string) => {
    if (!confirm(`Delete ${domain}?`)) return;

    try {
      await domainsApi.delete(domain);
      setDomains(domains.filter(d => d.domain !== domain));
      toast.success(`Deleted ${domain}`);
    } catch (error) {
      toast.error('Failed to delete domain');
    }
  };

  const handleReassignDomain = async (domain: string, newOwnerId: string) => {
    try {
      await domainsApi.update(domain, {
        owner: newOwnerId,
        origin_ip: domains.find(d => d.domain === domain)?.origin_ip || '',
        proxied: domains.find(d => d.domain === domain)?.proxied || false,
      });
      toast.success(`Reassigned ${domain}`);
      loadData();
    } catch (error) {
      toast.error('Failed to reassign domain');
    }
  };

  const filteredDomains = domains.filter(d => {
    const matchesSearch = d.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
      d.owner_email?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      d.origin_ip.includes(searchQuery);

    if (filterType === 'orphaned') return matchesSearch && !d.owner_exists;
    if (filterType === 'expiring') {
      const expires = d.tls_expires_at ? new Date(d.tls_expires_at) : null;
      const daysUntilExpiry = expires ? Math.ceil((expires.getTime() - Date.now()) / (1000 * 60 * 60 * 24)) : null;
      return matchesSearch && daysUntilExpiry !== null && daysUntilExpiry <= 30;
    }
    return matchesSearch;
  });

  const orphanedCount = domains.filter(d => !d.owner_exists).length;
  const expiringCount = domains.filter(d => {
    const expires = d.tls_expires_at ? new Date(d.tls_expires_at) : null;
    const daysUntilExpiry = expires ? Math.ceil((expires.getTime() - Date.now()) / (1000 * 60 * 60 * 24)) : null;
    return daysUntilExpiry !== null && daysUntilExpiry <= 30;
  }).length;

  const columns = [
    {
      key: 'domain',
      header: 'Domain',
      accessor: (d: DomainOverview) => (
        <div className="domain-cell">
          <span className="domain-name mono">{d.domain}</span>
          {!d.owner_exists && <Badge variant="warning" size="sm">Orphaned</Badge>}
        </div>
      ),
    },
    {
      key: 'owner',
      header: 'Owner',
      accessor: (d: DomainOverview) => (
        <div className="owner-cell">
          {d.owner_email ? (
            <span className="owner-email">{d.owner_email}</span>
          ) : (
            <span className="owner-missing">No owner</span>
          )}
        </div>
      ),
    },
    {
      key: 'origin_ip',
      header: 'Origin IP',
      accessor: (d: DomainOverview) => <span className="mono">{d.origin_ip}</span>,
    },
    {
      key: 'status',
      header: 'Status',
      accessor: (d: DomainOverview) => (
        <div className="status-cell">
          {d.proxied && <Badge variant="primary" size="sm">Proxied</Badge>}
          {d.tls_status && d.tls_status !== 'none' && (
            <Badge
              variant={d.tls_status === 'active' ? 'success' : 'warning'}
              size="sm"
            >
              TLS: {d.tls_status}
            </Badge>
          )}
        </div>
      ),
    },
    {
      key: 'tls_expiry',
      header: 'TLS Expiry',
      accessor: (d: DomainOverview) => {
        if (!d.tls_expires_at) return <span className="text-muted">—</span>;
        const expires = new Date(d.tls_expires_at);
        const daysUntilExpiry = Math.ceil((expires.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
        return (
          <div className="expiry-cell">
            <span className={daysUntilExpiry <= 30 ? 'text-warning' : ''}>
              {format(expires, 'MMM d, yyyy')}
            </span>
            {daysUntilExpiry <= 30 && (
              <Badge variant="warning" size="sm">{daysUntilExpiry}d</Badge>
            )}
          </div>
        );
      },
    },
    {
      key: 'updated',
      header: 'Updated',
      accessor: (d: DomainOverview) => (
        <span className="text-muted">
          {format(new Date(d.updated_at), 'MMM d, HH:mm')}
        </span>
      ),
    },
    {
      key: 'actions',
      header: 'Actions',
      accessor: (d: DomainOverview) => (
        <div className="actions-cell">
          <button
            className="action-btn"
            onClick={() => handleDeleteDomain(d.domain)}
            title="Delete domain"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="3 6 5 6 21 6" />
              <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
            </svg>
          </button>
        </div>
      ),
      width: '80px',
      align: 'center' as const,
    },
  ];

  return (
    <div className="admin-domains">
      <div className="page-header">
        <div className="header-content">
          <h1>Domain Management</h1>
          <p className="subtitle">{domains.length} total domains across all users</p>
        </div>
        <div className="header-actions">
          <Input
            placeholder="Search domains, owners, IPs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            icon={
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" />
                <path d="M21 21l-4.35-4.35" />
              </svg>
            }
          />
        </div>
      </div>

      <div className="filter-tabs">
        <button
          className={`filter-tab ${filterType === 'all' ? 'active' : ''}`}
          onClick={() => setFilterType('all')}
        >
          All Domains
          <span className="tab-count">{domains.length}</span>
        </button>
        <button
          className={`filter-tab ${filterType === 'orphaned' ? 'active' : ''}`}
          onClick={() => setFilterType('orphaned')}
        >
          Orphaned
          <span className="tab-count">{orphanedCount}</span>
        </button>
        <button
          className={`filter-tab ${filterType === 'expiring' ? 'active' : ''}`}
          onClick={() => setFilterType('expiring')}
        >
          Expiring Soon
          <span className="tab-count">{expiringCount}</span>
        </button>
      </div>

      <Card padding="none">
        <Table
          columns={columns}
          data={filteredDomains}
          keyExtractor={(d) => d.domain}
          loading={loading}
          emptyMessage={`No ${filterType === 'all' ? '' : filterType} domains found`}
        />
      </Card>

      {orphanedCount > 0 && (
        <Card className="orphaned-notice" variant="bordered">
          <div className="notice-content">
            <div className="notice-icon">⚠️</div>
            <div className="notice-text">
              <h3>Orphaned Domains Detected</h3>
              <p>
                {orphanedCount} domain{orphanedCount !== 1 ? 's' : ''} belong to deleted users.
                Consider reassigning or removing these domains.
              </p>
            </div>
            <Button variant="secondary" size="sm">
              Bulk Reassign
            </Button>
          </div>
        </Card>
      )}
    </div>
  );
}
