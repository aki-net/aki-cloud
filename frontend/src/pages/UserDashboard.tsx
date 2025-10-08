import { FormEvent, useEffect, useState } from 'react';
import { createDomain, deleteDomain, fetchDomains, updateDomain } from '../services/api';
import { DomainRecord, DomainTLSPayload, EncryptionMode } from '../types';
import { useAuth } from '../providers/AuthProvider';

type ModeChoice = 'auto' | EncryptionMode;

const TLS_MODE_OPTIONS: { value: ModeChoice; label: string }[] = [
  { value: 'auto', label: 'Auto (Recommended)' },
  { value: 'off', label: 'Off' },
  { value: 'flexible', label: 'Flexible' },
  { value: 'full', label: 'Full' },
  { value: 'full_strict', label: 'Full (Strict)' },
  { value: 'strict_origin_pull', label: 'Strict (Origin Pull)' },
];

export const UserDashboard = () => {
  const { user } = useAuth();
  const [domains, setDomains] = useState<DomainRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ domain: '', origin_ip: '', proxied: true, ttl: 60, tlsMode: 'auto' as ModeChoice });

  const buildTLSPayload = (choice: ModeChoice): DomainTLSPayload =>
    choice === 'auto' ? { use_recommended: true } : { use_recommended: false, mode: choice };

  const tlsPayloadForRecord = (record: DomainRecord): DomainTLSPayload =>
    record.tls.use_recommended ? { use_recommended: true } : { use_recommended: false, mode: (record.tls.mode as EncryptionMode) || 'flexible' };

  const effectiveMode = (record: DomainRecord): ModeChoice =>
    record.tls.use_recommended ? 'auto' : (record.tls.mode as EncryptionMode) || 'flexible';

  const statusBadge = (status: string): string => {
    switch (status) {
      case 'active':
        return 'success';
      case 'pending':
        return 'info';
      case 'errored':
        return 'danger';
      default:
        return 'secondary';
    }
  };

  const modeLabel = (value: ModeChoice): string => TLS_MODE_OPTIONS.find((option) => option.value === value)?.label ?? value;

  const load = async () => {
    setLoading(true);
    try {
      const data = await fetchDomains();
      setDomains(data);
    } catch (err) {
      setError('Failed to load domains');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load().catch(() => null);
  }, []);

  const onCreate = async (event: FormEvent) => {
    event.preventDefault();
    if (!form.domain || !form.origin_ip) {
      return;
    }
    try {
      const tls = buildTLSPayload(form.tlsMode);
      const record = await createDomain({
        domain: form.domain,
        origin_ip: form.origin_ip,
        proxied: form.proxied,
        ttl: form.ttl,
        owner: user?.id,
        tls,
      });
      setDomains((prev) => [...prev.filter((d) => d.domain !== record.domain), record]);
      setForm({ domain: '', origin_ip: '', proxied: true, ttl: 60, tlsMode: 'auto' });
    } catch (err) {
      setError('Failed to create domain');
    }
  };

  const toggleProxied = async (record: DomainRecord) => {
    try {
      const updated = await updateDomain(record.domain, {
        origin_ip: record.origin_ip,
        proxied: !record.proxied,
        ttl: record.ttl,
        tls: tlsPayloadForRecord(record),
      });
      setDomains((prev) => prev.map((item) => (item.domain === updated.domain ? updated : item)));
    } catch (err) {
      setError('Failed to update domain');
    }
  };

  const updateTLSMode = async (record: DomainRecord, choice: ModeChoice) => {
    try {
      const updated = await updateDomain(record.domain, {
        origin_ip: record.origin_ip,
        proxied: record.proxied,
        ttl: record.ttl,
        tls: buildTLSPayload(choice),
      });
      setDomains((prev) => prev.map((item) => (item.domain === updated.domain ? updated : item)));
    } catch (err) {
      setError('Failed to update TLS mode');
    }
  };

  const onDelete = async (record: DomainRecord) => {
    if (!window.confirm(`Delete ${record.domain}?`)) {
      return;
    }
    try {
      await deleteDomain(record.domain);
      setDomains((prev) => prev.filter((d) => d.domain !== record.domain));
    } catch (err) {
      setError('Failed to delete domain');
    }
  };

  return (
    <div className="grid">
      <div className="card">
        <h2 className="section-title">Your Domains</h2>
        <p className="alert">Changes may take up to 20 seconds to synchronize across edge nodes.</p>
        {loading ? (
          <p>Loading…</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Origin IP</th>
                <th>Proxy</th>
                <th>TLS Mode</th>
                <th>TLS Status</th>
                <th>TTL</th>
                <th>Updated</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {domains.map((record) => (
                <tr key={record.domain}>
                  <td>{record.domain}</td>
                  <td>{record.origin_ip}</td>
                  <td>
                    <button className="button secondary" onClick={() => toggleProxied(record)}>
                      {record.proxied ? 'Proxied' : 'DNS Only'}
                    </button>
                  </td>
                  <td>
                    <select
                      className="input"
                      value={effectiveMode(record)}
                      onChange={(e) => updateTLSMode(record, e.target.value as ModeChoice)}
                    >
                      {TLS_MODE_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <span className={`badge ${statusBadge(record.tls.status)}`}>{record.tls.status}</span>
                    {record.tls.certificate?.not_after && (
                      <div className="text-muted">exp. {new Date(record.tls.certificate.not_after).toLocaleDateString()}</div>
                    )}
                    {record.tls.use_recommended && record.tls.recommended_mode && (
                      <div className="text-muted">auto → {modeLabel(record.tls.recommended_mode as ModeChoice)}</div>
                    )}
                    {record.tls.last_error && <div className="text-muted">{record.tls.last_error}</div>}
                    {record.tls.origin_pull_secret?.ca_pem && (
                      <details>
                        <summary>Origin Pull CA</summary>
                        <pre className="code-block">{record.tls.origin_pull_secret.ca_pem}</pre>
                      </details>
                    )}
                    {record.tls.origin_pull_secret?.certificate_pem && (
                      <details>
                        <summary>Edge Client Cert</summary>
                        <pre className="code-block">{record.tls.origin_pull_secret.certificate_pem}</pre>
                      </details>
                    )}
                    {record.tls.origin_pull_secret?.fingerprint && (
                      <div className="text-muted">fingerprint {record.tls.origin_pull_secret.fingerprint}</div>
                    )}
                  </td>
                  <td>{record.ttl}s</td>
                  <td>{new Date(record.updated_at).toLocaleString()}</td>
                  <td>
                    <button className="button secondary" onClick={() => onDelete(record)}>
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {error && <div className="alert">{error}</div>}
      </div>

      <form className="card" onSubmit={onCreate}>
        <h3 className="section-title">Add Domain</h3>
        <label>
          Domain
          <input
            className="input"
            placeholder="example.com"
            value={form.domain}
            onChange={(e) => setForm((prev) => ({ ...prev, domain: e.target.value }))}
            required
          />
        </label>
        <label>
          Origin IP
          <input
            className="input"
            placeholder="203.0.113.10"
            value={form.origin_ip}
            onChange={(e) => setForm((prev) => ({ ...prev, origin_ip: e.target.value }))}
            required
          />
        </label>
        <label>
          TTL seconds
          <input
            className="input"
            type="number"
            min={30}
            value={form.ttl}
            onChange={(e) => setForm((prev) => ({ ...prev, ttl: Number(e.target.value) }))}
          />
        </label>
        <label>
          Edge TLS mode
          <select
            className="input"
            value={form.tlsMode}
            onChange={(e) => setForm((prev) => ({ ...prev, tlsMode: e.target.value as ModeChoice }))}
          >
            {TLS_MODE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          <small className="text-muted">Auto picks the safest option for your origin.</small>
        </label>
        <label className="flex">
          <input
            type="checkbox"
            checked={form.proxied}
            onChange={(e) => setForm((prev) => ({ ...prev, proxied: e.target.checked }))}
          />
          Proxy through edge network
        </label>
        <button className="button" type="submit">
          Create domain
        </button>
      </form>
    </div>
  );
};
