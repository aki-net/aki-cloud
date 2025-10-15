import React, { useState, useEffect, useCallback } from 'react';
import { Routes, Route, NavLink, useLocation } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import Switch from '../components/ui/Switch';
import PageHeader from '../components/PageHeader';
import { Extension, SearchBotMetrics, WAFDefinition } from '../types';
import { extensionsApi, waf as wafApi } from '../api/client';
import './AdminExtensions.css';

const EXTENSION_ICONS: Record<string, string> = {
  edge_cache: '🗄️',
  random_server_headers: '🎲',
  placeholder_pages: '🪧',
  searchbot_logs: '🤖',
};

const getExtensionIcon = (key: string) => EXTENSION_ICONS[key] ?? '🧩';

const formatBytes = (bytes?: number): string => {
  if (!bytes || Number.isNaN(bytes) || bytes <= 0) {
    return '0 B';
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, exponent);
  const digits = value >= 10 ? 0 : 1;
  return `${value.toFixed(digits)} ${units[exponent]}`;
};

const formatUpdated = (value?: string) => {
  if (!value) return 'never';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
};

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
                ext.status === 'active'
                  ? 'success'
                  : ext.status === 'beta'
                  ? 'warning'
                  : 'default'
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

function renderExtensionMeta(ext: Extension) {
  const config = ext.config || {};
  switch (ext.key) {
    case 'edge_cache': {
      const path = typeof config.path === 'string' ? config.path : '—';
      const zone = typeof config.zone_name === 'string' ? config.zone_name : '—';
      const maxSize = typeof config.max_size === 'string' ? config.max_size : '—';
      const inactive = typeof config.inactive === 'string' ? config.inactive : '—';
      return (
        <ul className="extension-meta">
          <li>
            <strong>Cache directory:</strong> {path}
          </li>
          <li>
            <strong>Zone:</strong> {zone}
          </li>
          <li>
            <strong>Max size:</strong> {maxSize}
          </li>
          <li>
            <strong>Inactive TTL:</strong> {inactive}
          </li>
        </ul>
      );
    }
    case 'random_server_headers': {
      const pool = Array.isArray(config.pool) ? config.pool : [];
      return (
        <ul className="extension-meta">
          <li>
            <strong>Header variants:</strong> {pool.length || 'unknown'}
          </li>
          <li>
            <strong>Sample:</strong> {pool.slice(0, 3).join(', ') || '—'}
          </li>
        </ul>
      );
    }
    case 'placeholder_pages': {
      const title =
        typeof config.title === 'string'
          ? config.title
          : 'Domain delegated to aki.cloud';
      const message =
        typeof config.message === 'string'
          ? config.message
          : 'Traffic reaches aki.cloud edge, origin not configured yet.';
      return (
        <ul className="extension-meta">
          <li>
            <strong>Headline:</strong> {title}
          </li>
          <li>
            <strong>Message:</strong> {message}
          </li>
        </ul>
      );
    }
    case 'searchbot_logs': {
      const metrics = (ext.metrics ?? {}) as SearchBotMetrics;
      const nodes = Array.isArray(metrics.nodes) ? metrics.nodes : [];
      return (
        <div className="extension-meta searchbot-meta">
          <div className="searchbot-meta-summary">
            <span>
              <strong>Log directory:</strong> {metrics.log_dir ?? '—'}
            </span>
            {typeof metrics.file_limit_bytes === 'number' && (
              <span>
                <strong>File limit:</strong> {formatBytes(metrics.file_limit_bytes)}
              </span>
            )}
          </div>
          <ul className="searchbot-meta-list">
            {nodes.length === 0 ? (
              <li className="searchbot-meta-empty">No log usage reported yet.</li>
            ) : (
              nodes.map((node) => (
                <li key={node.node_id} className="searchbot-meta-item">
                  <div className="searchbot-meta-row">
                    <span className="searchbot-meta-node">
                      {node.node_name || node.node_id}
                    </span>
                    <span className="searchbot-meta-size">
                      {formatBytes(node.total_bytes)}
                    </span>
                  </div>
                  {Array.isArray(node.bots) && node.bots.length > 0 && (
                    <div className="searchbot-meta-bots">
                      {node.bots.map((bot) => (
                        <span key={bot.key}>
                          {bot.label}: {formatBytes(bot.bytes)}
                        </span>
                      ))}
                    </div>
                  )}
                </li>
              ))
            )}
          </ul>
        </div>
      );
    }
    default:
      return null;
  }
}

function SystemExtensions() {
  const [extensions, setExtensions] = useState<Extension[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updatingKey, setUpdatingKey] = useState<string | null>(null);
  const [actionKey, setActionKey] = useState<string | null>(null);

  const loadExtensions = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await extensionsApi.list();
      setExtensions(data);
    } catch (err: any) {
      console.error('Failed to load extensions', err);
      setError(err?.response?.data?.error || 'Failed to load extensions');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadExtensions();
  }, [loadExtensions]);

  const handleToggle = useCallback(
    async (key: string, enabled: boolean) => {
      setUpdatingKey(key);
      try {
        const updated = await extensionsApi.update(key, { enabled });
        setExtensions((prev) =>
          prev.map((ext) => (ext.key === updated.key ? updated : ext)),
        );
        toast.success(`${updated.name} ${enabled ? 'enabled' : 'disabled'}`);
      } catch (err: any) {
        console.error('Failed to update extension', err);
        toast.error(err?.response?.data?.error || 'Failed to update extension');
      } finally {
        setUpdatingKey(null);
      }
    },
    [],
  );

  const handleAction = useCallback(
    async (key: string, action: string) => {
      const actionIdentifier = `${key}:${action}`;
      setActionKey(actionIdentifier);
      try {
        const response = await extensionsApi.action(key, action);
        toast.success(response.status || 'Action completed');
        await loadExtensions();
      } catch (err: any) {
        console.error('Extension action failed', err);
        toast.error(err?.response?.data?.error || 'Action failed');
      } finally {
        setActionKey(null);
      }
    },
    [],
  );

  return (
    <div className="extensions-hub">
      {error && (
        <Card className="extension-alert">
          <div className="extension-alert-content">
            <span>{error}</span>
            <Button variant="primary" size="sm" onClick={loadExtensions}>
              Retry
            </Button>
          </div>
        </Card>
      )}

      {loading && extensions.length === 0 && (
        <Card className="extension-card">
          <div className="extension-loading">Loading extensions…</div>
        </Card>
      )}

      <div className="extensions-grid">
        {extensions.map((ext) => {
          const meta = renderExtensionMeta(ext);
          const icon = getExtensionIcon(ext.key);
          const actions = ext.actions ?? [];
          const statusVariant = ext.enabled ? 'success' : 'default';
          const scopeLabel =
            ext.scope === 'domain'
              ? 'Per-domain'
              : ext.scope === 'node'
              ? 'Per-node'
              : 'Global';
          const updating = updatingKey === ext.key;
          return (
            <Card key={ext.key} className="extension-card">
              <div className="extension-header">
                <div className="extension-header-left">
                  <span className="extension-icon" role="img" aria-label={ext.name}>
                    {icon}
                  </span>
                  <div className="extension-header-text">
                    <h3 className="extension-name">{ext.name}</h3>
                    <div className="extension-tags">
                      <Badge variant="secondary" size="sm">
                        {ext.category}
                      </Badge>
                      <Badge variant="secondary" size="sm">
                        {scopeLabel}
                      </Badge>
                    </div>
                  </div>
                </div>
                <div className="extension-status">
                  <Badge variant={statusVariant} size="sm">
                    {ext.enabled ? 'enabled' : 'disabled'}
                  </Badge>
                  <Switch
                    checked={ext.enabled}
                    disabled={updating}
                    onChange={(checked) => handleToggle(ext.key, checked)}
                  />
                </div>
              </div>

              <p className="extension-description">{ext.description}</p>

              {meta}

              <div className="extension-footer">
                <div className="extension-updated">
                  <span>Updated: {formatUpdated(ext.updated_at)}</span>
                  {ext.updated_by && <span> · by {ext.updated_by}</span>}
                </div>
                <div className="extension-actions">
                  {actions.map((action) => (
                    <Button
                      key={`${ext.key}-${action.key}`}
                      variant="ghost"
                      size="sm"
                      disabled={!ext.enabled}
                      loading={actionKey === `${ext.key}:${action.key}`}
                      onClick={() => handleAction(ext.key, action.key)}
                    >
                      {action.label || action.key}
                    </Button>
                  ))}
                </div>
              </div>
            </Card>
          );
        })}

        {!loading && !error && extensions.length === 0 && (
          <Card className="extension-card">
            <div className="extension-empty">
              <p>No extensions available yet.</p>
            </div>
          </Card>
        )}
      </div>
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
  const [wafDefinitions, setWafDefinitions] = useState<WAFDefinition[]>([]);
  const [wafLoading, setWafLoading] = useState(true);
  const [wafError, setWafError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setWafLoading(true);
      setWafError(null);
      try {
        const defs = await wafApi.definitions();
        if (!cancelled) {
          setWafDefinitions(defs);
        }
      } catch (err: any) {
        if (!cancelled) {
          console.error('Failed to load WAF definitions', err);
          setWafError('Failed to load WAF presets');
        }
      } finally {
        if (!cancelled) {
          setWafLoading(false);
        }
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, []);

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
              onChange={(checked) =>
                setSettings({ ...settings, ddosProtection: checked })
              }
            />
          </div>
          <div className="setting-item">
            <div className="setting-info">
              <h4>Bot Fighting</h4>
              <p>Identify and block malicious bot traffic</p>
            </div>
            <Switch
              checked={settings.botFighting}
              onChange={(checked) =>
                setSettings({ ...settings, botFighting: checked })
              }
            />
          </div>
          <div className="setting-item">
            <div className="setting-info">
              <h4>SSL Enforcement</h4>
              <p>Force all connections to use HTTPS</p>
            </div>
            <Switch
              checked={settings.sslEnforcement}
              onChange={(checked) =>
                setSettings({ ...settings, sslEnforcement: checked })
              }
            />
          </div>
          <div className="setting-item">
            <div className="setting-info">
              <h4>HTTP/3 Support</h4>
              <p>Enable QUIC protocol for faster connections</p>
            </div>
            <Switch
              checked={settings.http3Support}
              onChange={(checked) =>
                setSettings({ ...settings, http3Support: checked })
              }
            />
          </div>
          <div className="setting-item">
            <div className="setting-info">
              <h4>Zero Trust Network</h4>
              <p>Implement zero trust security model</p>
            </div>
            <Switch
              checked={settings.zeroTrust}
              onChange={(checked) =>
                setSettings({ ...settings, zeroTrust: checked })
              }
            />
          </div>
        </div>
      </Card>

      <Card
        className="waf-card"
        title="Web Application Firewall"
        description="Built-in presets that can be enforced globally or per domain."
        variant="bordered"
      >
        {wafLoading ? (
          <p className="waf-presets-empty">Loading presets…</p>
        ) : wafError ? (
          <p className="waf-presets-empty">{wafError}</p>
        ) : wafDefinitions.length === 0 ? (
          <p className="waf-presets-empty">No presets available yet.</p>
        ) : (
          <>
            <ul className="waf-presets-list">
              {wafDefinitions.map((definition) => (
                <li key={definition.key} className="waf-preset-item">
                  <div className="waf-preset-head">
                    <span className="waf-preset-name">{definition.name}</span>
                    <span className="waf-preset-category">{definition.category}</span>
                  </div>
                  <p className="waf-preset-description">{definition.description}</p>
                </li>
              ))}
            </ul>
            <p className="waf-presets-hint">
              Toggle presets per domain from the Domains list to restrict access (e.g. allow only verified Googlebot traffic).
            </p>
          </>
        )}
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
                <p>Trigger: {workflow.trigger}</p>
              </div>
              <div className="workflow-meta">
                <Badge
                  variant={workflow.status === 'active' ? 'success' : 'default'}
                  size="sm"
                >
                  {workflow.status}
                </Badge>
                <span className="workflow-run">Last run: {workflow.lastRun}</span>
                <span className="workflow-run">Next run: {workflow.nextRun}</span>
              </div>
              <div className="workflow-actions">
                <Switch
                  checked={workflow.status === 'active'}
                  size="sm"
                />
                <Button variant="ghost" size="sm">
                  Edit
                </Button>
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
                      <Badge key={perm} variant="default" size="sm">
                        {perm}
                      </Badge>
                    ))}
                  </div>
                </div>
              </div>
              <div className="key-actions">
                <Button variant="ghost" size="sm">
                  Regenerate
                </Button>
                <Button variant="danger" size="sm">
                  Revoke
                </Button>
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
    { path: '/extensions/system', label: 'System', icon: '🛠️' },
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
            className={({ isActive }) =>
              `extension-tab ${
                (isActive && location.pathname === tab.path) ||
                (tab.path === '/extensions' && location.pathname === '/extensions')
                  ? 'active'
                  : ''
              }`
            }
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
          <Route path="system" element={<SystemExtensions />} />
        </Routes>
      </div>
    </div>
  );
}
