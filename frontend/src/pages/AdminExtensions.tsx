import React, { useState, useEffect, useCallback } from 'react';
import { Routes, Route, NavLink, useLocation } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import Switch from '../components/ui/Switch';
import PageHeader from '../components/PageHeader';
import {
  Extension,
  SearchBotMetrics,
  WAFDefinition,
  BackupStatus,
  BackupDescriptor,
  BackupRunResult,
} from '../types';
import { extensionsApi, waf as wafApi, backups as backupApi } from '../api/client';
import './AdminExtensions.css';

const EXTENSION_ICONS: Record<string, string> = {
  edge_cache: '🗄️',
  random_server_headers: '🎲',
  placeholder_pages: '🪧',
  searchbot_logs: '🤖',
  mega_backups: '💾',
};

const getExtensionIcon = (key: string) => EXTENSION_ICONS[key] ?? '🧩';

const sortExtensionsList = (items: Extension[]) =>
  items
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name) || a.key.localeCompare(b.key));

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

const BACKUP_DATASETS = [
  { value: 'domains', label: 'Domains', required: true },
  { value: 'users', label: 'Users' },
  { value: 'extensions', label: 'Extensions' },
  { value: 'nodes', label: 'Nodes' },
  { value: 'edge_health', label: 'Edge health' },
];

type MegaNodeForm = {
  name: string;
  enabled: boolean;
  username: string;
  password: string;
  passwordSet: boolean;
  schedule: string;
  include: string[];
  retention: number;
};

type MegaConfigForm = {
  include: string[];
  scheduleDefault: string;
  nodes: MegaNodeForm[];
};

function ensureDomains(list: string[]): string[] {
  const set = new Set(list.map((item) => item.trim()).filter(Boolean));
  set.add('domains');
  return Array.from(set);
}

function parseMegaConfig(extension: Extension): MegaConfigForm {
  const raw = (extension.config ?? {}) as Record<string, any>;
  const include = ensureDomains(
    Array.isArray(raw.include)
      ? (raw.include as unknown[])
          .map((item) => (typeof item === 'string' ? item : String(item)))
      : ['domains'],
  );
  const scheduleDefault =
    typeof raw.schedule_default === 'string' && raw.schedule_default.trim() !== ''
      ? raw.schedule_default.trim()
      : '24h';
  const nodesRaw = (raw.nodes as Record<string, any>) ?? {};
  const nodes: MegaNodeForm[] = Object.entries(nodesRaw).map(([name, value]) => {
    const nodeConfig = (value ?? {}) as Record<string, any>;
    const includeOverride = Array.isArray(nodeConfig.include)
      ? (nodeConfig.include as unknown[])
          .map((item) => (typeof item === 'string' ? item : String(item)))
      : include;
    let retention = 14;
    if (typeof nodeConfig.retention === 'number') {
      retention = nodeConfig.retention;
    } else if (
      typeof nodeConfig.retention === 'string' &&
      Number.isFinite(Number.parseInt(nodeConfig.retention, 10))
    ) {
      retention = Number.parseInt(nodeConfig.retention, 10);
    }
    return {
      name,
      enabled:
        typeof nodeConfig.enabled === 'boolean' ? nodeConfig.enabled : extension.enabled,
      username:
        typeof nodeConfig.username === 'string' ? nodeConfig.username : '',
      password: '',
      passwordSet: Boolean(nodeConfig.password_set),
      schedule:
        typeof nodeConfig.schedule === 'string' ? nodeConfig.schedule.trim() : '',
      include: ensureDomains(includeOverride),
      retention: retention > 0 ? retention : 14,
    };
  });
  if (nodes.length === 0) {
    nodes.push({
      name: 'node-1',
      enabled: extension.enabled,
      username: '',
      password: '',
      passwordSet: false,
      schedule: '',
      include,
      retention: 14,
    });
  }
  return {
    include,
    scheduleDefault,
    nodes,
  };
}

function MegaBackupControls({
  extension,
  onReload,
}: {
  extension: Extension;
  onReload: () => void;
}) {
  const [form, setForm] = useState<MegaConfigForm>(() => parseMegaConfig(extension));
  const [status, setStatus] = useState<BackupStatus | null>(null);
  const [history, setHistory] = useState<BackupDescriptor[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [runLoading, setRunLoading] = useState(false);
  const [restoreLoading, setRestoreLoading] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [fileUploading, setFileUploading] = useState<File | null>(null);
  const [fileRestoring, setFileRestoring] = useState<File | null>(null);
  const [restoreSettings, setRestoreSettings] = useState({
    wipeDomains: true,
    wipeUsers: false,
    wipeExtensions: false,
    wipeNodes: false,
    wipeEdge: false,
    includeUsers: false,
    includeExtensions: false,
    includeNodes: false,
    includeEdge: false,
  });
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(() => new Set<string>());
  const [removedNodes, setRemovedNodes] = useState<string[]>([]);
  const [newNode, setNewNode] = useState('');

  useEffect(() => {
    const parsed = parseMegaConfig(extension);
    setForm(parsed);
    setRemovedNodes([]);
    setExpandedNodes(() => {
      const next = new Set<string>();
      if (parsed.nodes.length === 1) {
        next.add(parsed.nodes[0].name);
      }
      return next;
    });
  }, [extension]);

  const refreshStatus = useCallback(async () => {
    try {
      setLoading(true);
      const [statusRes, listRes] = await Promise.all([
        backupApi.status(),
        backupApi.list(),
      ]);
      setStatus(statusRes);
      const sorted = (listRes || []).slice().sort((a, b) => {
        const at = new Date(a.createdAt ?? 0).getTime();
        const bt = new Date(b.createdAt ?? 0).getTime();
        return bt - at;
      });
      setHistory(sorted);
    } catch (err: any) {
      console.error('failed to load backup info', err);
      toast.error(err?.response?.data?.error || 'Failed to load backup status');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshStatus();
  }, [refreshStatus]);

  const updateNode = useCallback(
    (name: string, patch: Partial<MegaNodeForm>) => {
      setForm((prev) => ({
        ...prev,
        nodes: prev.nodes.map((node) =>
          node.name === name ? { ...node, ...patch } : node,
        ),
      }));
    },
    [],
  );

  const toggleDataset = useCallback(
    (target: 'global' | string, dataset: string, checked: boolean) => {
      setForm((prev) => {
        if (target === 'global') {
          const include = new Set(prev.include);
          if (checked) {
            include.add(dataset);
          } else if (dataset !== 'domains') {
            include.delete(dataset);
          }
          return { ...prev, include: ensureDomains(Array.from(include)) };
        }
        return {
          ...prev,
          nodes: prev.nodes.map((node) => {
            if (node.name !== target) {
              return node;
            }
            const include = new Set(node.include);
            if (checked) {
              include.add(dataset);
            } else if (dataset !== 'domains') {
              include.delete(dataset);
            }
            return { ...node, include: ensureDomains(Array.from(include)) };
          }),
        };
      });
    },
    [],
  );

  const toggleNodePanel = useCallback((name: string) => {
    setExpandedNodes((prev) => {
      const next = new Set(prev);
      if (next.has(name)) {
        next.delete(name);
      } else {
        next.add(name);
      }
      return next;
    });
  }, []);

  const handleRemoveNode = useCallback((name: string) => {
    setForm((prev) => ({
      ...prev,
      nodes: prev.nodes.filter((node) => node.name !== name),
    }));
    setRemovedNodes((prev) => (prev.includes(name) ? prev : [...prev, name]));
    setExpandedNodes((prev) => {
      const next = new Set(prev);
      next.delete(name);
      return next;
    });
  }, []);

  const addNode = useCallback(() => {
    const trimmed = newNode.trim();
    if (!trimmed) {
      return;
    }
    if (form.nodes.some((node) => node.name === trimmed)) {
      toast.error('Node already configured');
      return;
    }
    setForm((prev) => ({
      ...prev,
      nodes: [
        ...prev.nodes,
        {
          name: trimmed,
          enabled: extension.enabled,
          username: '',
          password: '',
          passwordSet: false,
          schedule: '',
          include: ensureDomains(prev.include),
          retention: 14,
        },
      ],
    }));
    setRemovedNodes((prev) => prev.filter((node) => node !== trimmed));
    setExpandedNodes((prev) => {
      const next = new Set(prev);
      next.add(trimmed);
      return next;
    });
    setNewNode('');
  }, [extension.enabled, form.include, form.nodes, newNode]);

  const handleSave = useCallback(async () => {
    try {
      setSaving(true);
      const payload: Record<string, unknown> = {
        include: ensureDomains(form.include),
        schedule_default: form.scheduleDefault.trim() || '24h',
      };
      const nodePayload: Record<string, unknown> = {};
      form.nodes.forEach((node) => {
        const nodeConfig: Record<string, unknown> = {
          enabled: node.enabled,
          username: node.username.trim(),
          include: ensureDomains(node.include),
          retention: node.retention,
        };
        if (node.schedule.trim() !== '') {
          nodeConfig.schedule = node.schedule.trim();
        }
        if (node.password.trim() !== '') {
          nodeConfig.password = node.password.trim();
        }
        nodePayload[node.name] = nodeConfig;
      });
      removedNodes.forEach((name) => {
        nodePayload[name] = null;
      });
      if (Object.keys(nodePayload).length > 0) {
        payload.nodes = nodePayload;
      }
      await extensionsApi.update(extension.key, { config: payload });
      toast.success('Backup settings saved');
      onReload();
      // Clear password fields after successful save
      setForm((prev) => ({
        ...prev,
        nodes: prev.nodes.map((node) => ({ ...node, password: '' })),
      }));
      setRemovedNodes([]);
    } catch (err: any) {
      console.error('failed to save backup settings', err);
      toast.error(err?.response?.data?.error || 'Failed to save backup settings');
    } finally {
      setSaving(false);
    }
  }, [extension.key, form, onReload, removedNodes]);

  const buildIncludeList = useCallback(() => {
    const include = new Set<string>(['domains']);
    if (restoreSettings.includeUsers) {
      include.add('users');
    }
    if (restoreSettings.includeExtensions) {
      include.add('extensions');
    }
    if (restoreSettings.includeNodes) {
      include.add('nodes');
    }
    if (restoreSettings.includeEdge) {
      include.add('edge_health');
    }
    return Array.from(include);
  }, [restoreSettings]);

  const handleRunBackup = useCallback(async () => {
    try {
      setRunLoading(true);
      const result: BackupRunResult = await backupApi.run({});
      toast.success(`Backup ${result.name || 'completed'}`);
      await refreshStatus();
    } catch (err: any) {
      console.error('backup run failed', err);
      toast.error(err?.response?.data?.error || 'Backup run failed');
    } finally {
      setRunLoading(false);
    }
  }, [refreshStatus]);

  const handleRestore = useCallback(
    async (name: string) => {
      if (
        !window.confirm(
          `Restore backup ${name}? This will overwrite selected datasets on this node.`,
        )
      ) {
        return;
      }
      try {
        setRestoreLoading(name);
        const includes = buildIncludeList();
        await backupApi.restore({
          name,
          include: includes,
          wipe: {
            domains: restoreSettings.wipeDomains,
            users: restoreSettings.wipeUsers,
            extensions: restoreSettings.wipeExtensions,
            nodes: restoreSettings.wipeNodes,
            edge_health: restoreSettings.wipeEdge,
          },
        });
        toast.success('Backup restored');
        await refreshStatus();
      } catch (err: any) {
        console.error('restore failed', err);
        toast.error(err?.response?.data?.error || 'Restore failed');
      } finally {
        setRestoreLoading(null);
      }
    },
    [buildIncludeList, refreshStatus, restoreSettings],
  );

  const handleUploadFile = useCallback(async () => {
    if (!fileUploading) {
      toast.error('Select a backup file first');
      return;
    }
    try {
      setUploading(true);
      await backupApi.uploadFile(fileUploading, fileUploading.name);
      toast.success('Backup uploaded to Mega');
      setFileUploading(null);
      await refreshStatus();
    } catch (err: any) {
      console.error('upload failed', err);
      toast.error(err?.response?.data?.error || 'Upload failed');
    } finally {
      setUploading(false);
    }
  }, [fileUploading, refreshStatus]);

  const MANUAL_RESTORE_KEY = '__manual__';

  const handleRestoreFromFile = useCallback(async () => {
    if (!fileRestoring) {
      toast.error('Select a backup file to restore');
      return;
    }
    try {
      setRestoreLoading(MANUAL_RESTORE_KEY);
      const include = buildIncludeList();
      await backupApi.restoreFromFile({
        file: fileRestoring,
        include,
        wipe: {
          domains: restoreSettings.wipeDomains,
          users: restoreSettings.wipeUsers,
          extensions: restoreSettings.wipeExtensions,
          nodes: restoreSettings.wipeNodes,
          edge_health: restoreSettings.wipeEdge,
        },
      });
      toast.success('Backup restored from file');
      setFileRestoring(null);
      await refreshStatus();
    } catch (err: any) {
      console.error('restore from file failed', err);
      toast.error(err?.response?.data?.error || 'Restore failed');
    } finally {
      setRestoreLoading(null);
    }
  }, [buildIncludeList, fileRestoring, refreshStatus, restoreSettings]);

  const renderDatasetCheckbox = (target: 'global' | string, dataset: { value: string; label: string; required?: boolean }) => (
    <label key={`${target}-${dataset.value}`} className="backup-dataset-item">
      <input
        type="checkbox"
        checked={
          target === 'global'
            ? form.include.includes(dataset.value)
            : form.nodes.find((node) => node.name === target)?.include.includes(dataset.value) ??
              false
        }
        onChange={(event) => toggleDataset(target, dataset.value, event.target.checked)}
        disabled={dataset.required}
      />
      {dataset.label}
    </label>
  );

  return (
    <div className="backup-panel">
      <div className="backup-status">
        <div className="backup-status-row">
          <span className="backup-status-label">Service status</span>
          <span className="backup-status-value">
            {status?.enabled ? 'Enabled' : 'Disabled'}
            {status?.running && ' · running'}
          </span>
        </div>
        <div className="backup-status-row">
          <span className="backup-status-label">Last backup</span>
          <span className="backup-status-value">
            {status?.lastBackupName
              ? `${status.lastBackupName} · ${formatUpdated(status.lastRunCompletedAt)}`
              : 'Never'}
          </span>
        </div>
        <div className="backup-status-row">
          <span className="backup-status-label">Next run</span>
          <span className="backup-status-value">
            {status?.nextRunAt ? formatUpdated(status.nextRunAt) : 'Not scheduled'}
          </span>
        </div>
        <div className="backup-status-row">
          <span className="backup-status-label">Credentials</span>
          <span className="backup-status-value">
            {status?.hasCredentials ? 'Configured' : 'Missing'}
          </span>
        </div>
        {status?.lastError && (
          <div className="backup-status-row error">
            <span className="backup-status-label">Last error</span>
            <span className="backup-status-value">{status.lastError}</span>
          </div>
        )}
        <div className="backup-status-actions">
          <Button
            variant="primary"
            size="sm"
            disabled={runLoading}
            onClick={handleRunBackup}
          >
            {runLoading ? 'Running…' : 'Run backup now'}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={refreshStatus}
            disabled={loading}
          >
            Refresh
          </Button>
        </div>
      </div>

      <div className="backup-manual">
        <div className="backup-manual-section">
          <h4>Upload backup</h4>
          <p className="backup-manual-description">
            Push a local archive to Mega.nz without waiting for the scheduler.
          </p>
          <div className="backup-manual-controls">
            <input
              type="file"
              accept=".gz"
              onChange={(event) => setFileUploading(event.target.files?.[0] ?? null)}
            />
            <Button
              variant="primary"
              size="sm"
              onClick={handleUploadFile}
              disabled={!fileUploading || uploading}
            >
              {uploading ? 'Uploading…' : 'Upload'}
            </Button>
          </div>
          {fileUploading && <span className="backup-file-note">{fileUploading.name}</span>}
        </div>
        <div className="backup-manual-section">
          <h4>Restore from file</h4>
          <p className="backup-manual-description">
            Apply a local backup directly to this node. Domains are always restored.
          </p>
          <div className="backup-manual-controls">
            <input
              type="file"
              accept=".gz"
              onChange={(event) => setFileRestoring(event.target.files?.[0] ?? null)}
            />
            <div className="backup-restore-options">
              <div className="backup-restore-column">
                <span className="backup-restore-title">Include datasets</span>
                <label className="backup-restore-toggle">
                  <input
                    type="checkbox"
                    checked={restoreSettings.includeUsers}
                    onChange={(event) =>
                      setRestoreSettings((prev) => ({
                        ...prev,
                        includeUsers: event.target.checked,
                      }))
                    }
                  />
                  Users
                </label>
                <label className="backup-restore-toggle">
                  <input
                    type="checkbox"
                    checked={restoreSettings.includeExtensions}
                    onChange={(event) =>
                      setRestoreSettings((prev) => ({
                        ...prev,
                        includeExtensions: event.target.checked,
                      }))
                    }
                  />
                  Extensions
                </label>
                <label className="backup-restore-toggle">
                  <input
                    type="checkbox"
                    checked={restoreSettings.includeNodes}
                    onChange={(event) =>
                      setRestoreSettings((prev) => ({
                        ...prev,
                        includeNodes: event.target.checked,
                      }))
                    }
                  />
                  Nodes
                </label>
                <label className="backup-restore-toggle">
                  <input
                    type="checkbox"
                    checked={restoreSettings.includeEdge}
                    onChange={(event) =>
                      setRestoreSettings((prev) => ({
                        ...prev,
                        includeEdge: event.target.checked,
                      }))
                    }
                  />
                  Edge health
                </label>
              </div>
              <div className="backup-restore-column">
                <span className="backup-restore-title">Wipe existing</span>
                <label className="backup-restore-toggle">
                  <input
                    type="checkbox"
                    checked={restoreSettings.wipeDomains}
                    onChange={(event) =>
                      setRestoreSettings((prev) => ({
                        ...prev,
                        wipeDomains: event.target.checked,
                      }))
                    }
                  />
                  Domains
                </label>
                <label className="backup-restore-toggle">
                  <input
                    type="checkbox"
                    checked={restoreSettings.wipeUsers}
                    onChange={(event) =>
                      setRestoreSettings((prev) => ({
                        ...prev,
                        wipeUsers: event.target.checked,
                      }))
                    }
                  />
                  Users
                </label>
                <label className="backup-restore-toggle">
                  <input
                    type="checkbox"
                    checked={restoreSettings.wipeExtensions}
                    onChange={(event) =>
                      setRestoreSettings((prev) => ({
                        ...prev,
                        wipeExtensions: event.target.checked,
                      }))
                    }
                  />
                  Extensions
                </label>
                <label className="backup-restore-toggle">
                  <input
                    type="checkbox"
                    checked={restoreSettings.wipeNodes}
                    onChange={(event) =>
                      setRestoreSettings((prev) => ({
                        ...prev,
                        wipeNodes: event.target.checked,
                      }))
                    }
                  />
                  Nodes
                </label>
                <label className="backup-restore-toggle">
                  <input
                    type="checkbox"
                    checked={restoreSettings.wipeEdge}
                    onChange={(event) =>
                      setRestoreSettings((prev) => ({
                        ...prev,
                        wipeEdge: event.target.checked,
                      }))
                    }
                  />
                  Edge health
                </label>
              </div>
            </div>
            <Button
              variant="primary"
              size="sm"
              onClick={handleRestoreFromFile}
              disabled={!fileRestoring || restoreLoading === MANUAL_RESTORE_KEY}
            >
              {restoreLoading === MANUAL_RESTORE_KEY ? 'Restoring…' : 'Restore from file'}
            </Button>
            {fileRestoring && (
              <span className="backup-file-note">{fileRestoring.name}</span>
            )}
          </div>
        </div>
      </div>

      <div className="backup-history">
        <h4>Recent backups</h4>
        {history.length === 0 ? (
          <p className="backup-history-empty">No backups uploaded yet.</p>
        ) : (
          <ul>
            {history.slice(0, 5).map((item) => (
              <li key={item.name} className="backup-history-item">
                <div>
                  <strong>{item.name}</strong>
                  <div className="backup-history-meta">
                    {formatUpdated(item.createdAt)} ·{' '}
                    {item.sizeBytes ? `${(item.sizeBytes / (1024 * 1024)).toFixed(1)} MB` : 'unknown size'}
                  </div>
                  {item.includes && item.includes.length > 0 && (
                    <div className="backup-history-datasets">
                      Datasets: {item.includes.join(', ')}
                    </div>
                  )}
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => handleRestore(item.name)}
                  disabled={restoreLoading === item.name}
                >
                  {restoreLoading === item.name ? 'Restoring…' : 'Restore'}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="backup-config">
        <h4>Backup configuration</h4>
        <div className="backup-config-grid">
          <label>
            Default schedule
            <input
              type="text"
              value={form.scheduleDefault}
              onChange={(event) =>
                setForm((prev) => ({
                  ...prev,
                  scheduleDefault: event.target.value,
                }))
              }
              placeholder="24h"
            />
          </label>
          <div className="backup-datasets">
            <span>Default datasets</span>
            <div className="backup-dataset-list">
              {BACKUP_DATASETS.map((dataset) => renderDatasetCheckbox('global', dataset))}
            </div>
          </div>
        </div>

        <div className="backup-nodes">
          <div className="backup-nodes-header">
            <h5>Per-node overrides</h5>
            <div className="backup-add-node">
              <input
                type="text"
                placeholder="node name"
                value={newNode}
                onChange={(event) => setNewNode(event.target.value)}
              />
              <Button variant="ghost" size="sm" onClick={addNode}>
                Add node
              </Button>
            </div>
          </div>
          {form.nodes.map((node) => (
            <Card
              key={node.name}
              className={`backup-node-card ${
                expandedNodes.has(node.name) ? 'expanded' : 'collapsed'
              }`}
            >
              <div className="backup-node-header">
                <div className="backup-node-title">
                  <strong>{node.name}</strong>
                  {node.passwordSet && <span className="backup-password-flag">Password set</span>}
                  {!expandedNodes.has(node.name) && (
                    <div className="backup-node-summary">
                      <span>{node.username || 'No credentials'}</span>
                      <span>{node.schedule || `inherits ${form.scheduleDefault}`}</span>
                    </div>
                  )}
                </div>
                <div className="backup-node-actions">
                  <Switch
                    checked={node.enabled}
                    onChange={(checked) => updateNode(node.name, { enabled: checked })}
                  />
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => toggleNodePanel(node.name)}
                  >
                    {expandedNodes.has(node.name) ? 'Hide' : 'Configure'}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleRemoveNode(node.name)}
                  >
                    Remove
                  </Button>
                </div>
              </div>
              {expandedNodes.has(node.name) && (
                <>
                  <div className="backup-node-grid">
                    <label>
                      Username
                      <input
                        type="text"
                        value={node.username}
                        onChange={(event) =>
                          updateNode(node.name, { username: event.target.value })
                        }
                        placeholder="mega@example.com"
                      />
                    </label>
                    <label>
                      Password
                      <input
                        type="password"
                        value={node.password}
                        onChange={(event) =>
                          updateNode(node.name, { password: event.target.value })
                        }
                        placeholder={node.passwordSet ? 'Update to rotate secret' : 'Required'}
                      />
                    </label>
                    <label>
                      Schedule override
                      <input
                        type="text"
                        value={node.schedule}
                        onChange={(event) =>
                          updateNode(node.name, { schedule: event.target.value })
                        }
                        placeholder={form.scheduleDefault}
                      />
                    </label>
                    <label>
                      Retention (backups to keep)
                      <input
                        type="number"
                        min={1}
                        value={node.retention}
                        onChange={(event) =>
                          updateNode(node.name, {
                            retention: Number.parseInt(event.target.value, 10) || 1,
                          })
                        }
                      />
                    </label>
                  </div>
                  <div className="backup-datasets">
                    <span>Datasets</span>
                    <div className="backup-dataset-list">
                      {BACKUP_DATASETS.map((dataset) =>
                        renderDatasetCheckbox(node.name, dataset),
                      )}
                    </div>
                  </div>
                </>
              )}
            </Card>
          ))}
        </div>

        <div className="backup-config-actions">
          <Button variant="primary" size="sm" onClick={handleSave} disabled={saving}>
            {saving ? 'Saving…' : 'Save settings'}
          </Button>
        </div>
      </div>
    </div>
  );
}

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
    case 'mega_backups': {
      const include = Array.isArray(config.include)
        ? (config.include as unknown[])
            .map((item) => (typeof item === 'string' ? item : String(item)))
            .join(', ')
        : 'domains';
      const schedule =
        typeof config.schedule_default === 'string'
          ? config.schedule_default
          : '24h';
      const nodes = config.nodes as Record<string, any> | undefined;
      return (
        <ul className="extension-meta">
          <li>
            <strong>Default schedule:</strong> {schedule}
          </li>
          <li>
            <strong>Default datasets:</strong> {include || 'domains'}
          </li>
          <li>
            <strong>Configured nodes:</strong>{' '}
            {nodes ? Object.keys(nodes).length : 0}
          </li>
        </ul>
      );
    }
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
      setExtensions(sortExtensionsList(data));
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
          sortExtensionsList(
            prev.map((ext) => (ext.key === updated.key ? updated : ext)),
          ),
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

              {ext.key === 'mega_backups' ? (
                <>
                  {meta}
                  <MegaBackupControls extension={ext} onReload={loadExtensions} />
                </>
              ) : (
                meta
              )}

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
