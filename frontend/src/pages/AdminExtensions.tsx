import React, { useState } from 'react';
import { Routes, Route, NavLink, useLocation } from 'react-router-dom';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import Switch from '../components/ui/Switch';
import PageHeader from '../components/PageHeader';
import './AdminExtensions.css';

function ExtensionsHub() {
  const [extensions] = useState([
    {
      id: 'rate-limiting',
      name: 'Rate Limiting',
      description: 'Advanced rate limiting and throttling for your domains',
      icon: '🚦',
      status: 'active',
      version: '2.1.0',
    },
    {
      id: 'geo-routing',
      name: 'Geo Routing',
      description: 'Route traffic based on geographic location',
      icon: '🌍',
      status: 'inactive',
      version: '1.5.2',
    },
    {
      id: 'waf',
      name: 'Web Application Firewall',
      description: 'Protect against common web exploits and attacks',
      icon: '🛡️',
      status: 'active',
      version: '3.0.1',
    },
    {
      id: 'analytics-pro',
      name: 'Analytics Pro',
      description: 'Advanced analytics and real-time monitoring',
      icon: '📊',
      status: 'beta',
      version: '1.0.0-beta.3',
    },
    {
      id: 'load-balancer',
      name: 'Load Balancer',
      description: 'Distribute traffic across multiple origin servers',
      icon: '⚖️',
      status: 'inactive',
      version: '2.2.0',
    },
    {
      id: 'image-optimizer',
      name: 'Image Optimizer',
      description: 'Automatic image optimization and WebP conversion',
      icon: '🖼️',
      status: 'active',
      version: '1.8.4',
    },
  ]);

  return (
    <div className="extensions-grid">
      {extensions.map((ext) => (
        <Card key={ext.id} className="extension-card">
          <div className="extension-header">
            <span className="extension-icon">{ext.icon}</span>
            <Badge
              variant={
                ext.status === 'active' ? 'success' :
                ext.status === 'beta' ? 'warning' :
                'default'
              }
              size="sm"
            >
              {ext.status}
            </Badge>
          </div>
          <h3 className="extension-name">{ext.name}</h3>
          <p className="extension-description">{ext.description}</p>
          <div className="extension-footer">
            <span className="extension-version">v{ext.version}</span>
            <Button variant="ghost" size="sm">
              {ext.status === 'active' ? 'Configure' : 'Enable'}
            </Button>
          </div>
        </Card>
      ))}
    </div>
  );
}

function SecurityCenter() {
  const [settings, setSettings] = useState({
    ddosProtection: true,
    botFighting: true,
    sslEnforcement: false,
    http3Support: false,
    zeroTrust: false,
  });

  return (
    <div className="security-center">
      <Card title="Security Settings">
        <div className="settings-list">
          <div className="setting-item">
            <div className="setting-info">
              <h4>DDoS Protection</h4>
              <p>Automatic detection and mitigation of DDoS attacks</p>
            </div>
            <Switch
              checked={settings.ddosProtection}
              onChange={(checked) => setSettings({ ...settings, ddosProtection: checked })}
            />
          </div>
          <div className="setting-item">
            <div className="setting-info">
              <h4>Bot Fighting</h4>
              <p>Identify and block malicious bot traffic</p>
            </div>
            <Switch
              checked={settings.botFighting}
              onChange={(checked) => setSettings({ ...settings, botFighting: checked })}
            />
          </div>
          <div className="setting-item">
            <div className="setting-info">
              <h4>SSL Enforcement</h4>
              <p>Force all connections to use HTTPS</p>
            </div>
            <Switch
              checked={settings.sslEnforcement}
              onChange={(checked) => setSettings({ ...settings, sslEnforcement: checked })}
            />
          </div>
          <div className="setting-item">
            <div className="setting-info">
              <h4>HTTP/3 Support</h4>
              <p>Enable QUIC protocol for faster connections</p>
            </div>
            <Switch
              checked={settings.http3Support}
              onChange={(checked) => setSettings({ ...settings, http3Support: checked })}
            />
          </div>
          <div className="setting-item">
            <div className="setting-info">
              <h4>Zero Trust Network</h4>
              <p>Implement zero trust security model</p>
            </div>
            <Switch
              checked={settings.zeroTrust}
              onChange={(checked) => setSettings({ ...settings, zeroTrust: checked })}
            />
          </div>
        </div>
      </Card>

      <Card title="Threat Intelligence" className="threat-card">
        <div className="threat-stats">
          <div className="threat-stat">
            <span className="stat-value">2,847</span>
            <span className="stat-label">Threats Blocked Today</span>
          </div>
          <div className="threat-stat">
            <span className="stat-value">99.7%</span>
            <span className="stat-label">Success Rate</span>
          </div>
          <div className="threat-stat">
            <span className="stat-value">12ms</span>
            <span className="stat-label">Avg Response Time</span>
          </div>
        </div>
      </Card>
    </div>
  );
}

function Automation() {
  const [workflows] = useState([
    {
      id: 1,
      name: 'Auto-renew SSL Certificates',
      trigger: 'Time-based',
      status: 'active',
      lastRun: '2 hours ago',
      nextRun: 'In 22 hours',
    },
    {
      id: 2,
      name: 'Failover to backup origin',
      trigger: 'Health check failure',
      status: 'active',
      lastRun: '3 days ago',
      nextRun: 'On trigger',
    },
    {
      id: 3,
      name: 'Scale edge nodes',
      trigger: 'Traffic threshold',
      status: 'paused',
      lastRun: '1 week ago',
      nextRun: '—',
    },
    {
      id: 4,
      name: 'Purge cache on deploy',
      trigger: 'Webhook',
      status: 'active',
      lastRun: 'Yesterday',
      nextRun: 'On trigger',
    },
  ]);

  return (
    <div className="automation-page">
      <Card title="Automation Workflows">
        <div className="workflows-list">
          {workflows.map((workflow) => (
            <div key={workflow.id} className="workflow-item">
              <div className="workflow-info">
                <h4>{workflow.name}</h4>
                <div className="workflow-meta">
                  <Badge variant="info" size="sm">{workflow.trigger}</Badge>
                  <span className="meta-text">Last run: {workflow.lastRun}</span>
                  <span className="meta-text">Next: {workflow.nextRun}</span>
                </div>
              </div>
              <div className="workflow-actions">
                <Switch
                  checked={workflow.status === 'active'}
                  size="sm"
                />
                <Button variant="ghost" size="sm">Edit</Button>
              </div>
            </div>
          ))}
        </div>
        <div className="add-workflow">
          <Button variant="primary">Create New Workflow</Button>
        </div>
      </Card>
    </div>
  );
}

function APIKeys() {
  const [keys] = useState([
    {
      id: 1,
      name: 'Production API Key',
      key: 'ak_prod_**********************3f2a',
      created: '2024-01-15',
      lastUsed: '5 minutes ago',
      permissions: ['read', 'write', 'delete'],
    },
    {
      id: 2,
      name: 'CI/CD Pipeline',
      key: 'ak_ci_**********************8b1c',
      created: '2024-02-20',
      lastUsed: '1 hour ago',
      permissions: ['read', 'write'],
    },
    {
      id: 3,
      name: 'Monitoring Service',
      key: 'ak_mon_**********************4d5e',
      created: '2024-03-10',
      lastUsed: '30 minutes ago',
      permissions: ['read'],
    },
  ]);

  return (
    <div className="api-keys-page">
      <Card title="API Keys Management">
        <div className="keys-list">
          {keys.map((key) => (
            <div key={key.id} className="key-item">
              <div className="key-info">
                <h4>{key.name}</h4>
                <code className="key-value">{key.key}</code>
                <div className="key-meta">
                  <span>Created: {key.created}</span>
                  <span>Last used: {key.lastUsed}</span>
                  <div className="key-permissions">
                    {key.permissions.map((perm) => (
                      <Badge key={perm} variant="default" size="sm">{perm}</Badge>
                    ))}
                  </div>
                </div>
              </div>
              <div className="key-actions">
                <Button variant="ghost" size="sm">Regenerate</Button>
                <Button variant="danger" size="sm">Revoke</Button>
              </div>
            </div>
          ))}
        </div>
        <div className="add-key">
          <Button variant="primary">Generate New API Key</Button>
        </div>
      </Card>
    </div>
  );
}

export default function AdminExtensions() {
  const location = useLocation();
  
  const tabs = [
    { path: '/extensions', label: 'Extensions', icon: '🧩' },
    { path: '/extensions/security', label: 'Security', icon: '🔒' },
    { path: '/extensions/automation', label: 'Automation', icon: '⚡' },
    { path: '/extensions/api-keys', label: 'API Keys', icon: '🔑' },
  ];

  return (
    <div className="admin-extensions">
      <PageHeader
        title="Extensions & Tools"
        subtitle="Enhance your infrastructure with powerful add-ons"
      />

      <div className="extensions-tabs">
        {tabs.map((tab) => (
          <NavLink
            key={tab.path}
            to={tab.path}
            className={({ isActive }) => `extension-tab ${
              (isActive && location.pathname === tab.path) || 
              (tab.path === '/extensions' && location.pathname === '/extensions')
                ? 'active' : ''
            }`}
            end
          >
            <span className="tab-icon">{tab.icon}</span>
            <span className="tab-label">{tab.label}</span>
          </NavLink>
        ))}
      </div>

      <div className="extensions-content">
        <Routes>
          <Route index element={<ExtensionsHub />} />
          <Route path="security" element={<SecurityCenter />} />
          <Route path="automation" element={<Automation />} />
          <Route path="api-keys" element={<APIKeys />} />
        </Routes>
      </div>
    </div>
  );
}
