import { FormEvent, useEffect, useState } from 'react';
import { createDomain, deleteDomain, fetchDomains, updateDomain } from '../services/api';
import { DomainRecord } from '../types';
import { useAuth } from '../providers/AuthProvider';

export const UserDashboard = () => {
  const { user } = useAuth();
  const [domains, setDomains] = useState<DomainRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ domain: '', origin_ip: '', proxied: false, ttl: 60 });

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
      const record = await createDomain({
        domain: form.domain,
        origin_ip: form.origin_ip,
        proxied: form.proxied,
        ttl: form.ttl,
        owner: user?.id,
      });
      setDomains((prev) => [...prev.filter((d) => d.domain !== record.domain), record]);
      setForm({ domain: '', origin_ip: '', proxied: false, ttl: 60 });
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
      });
      setDomains((prev) => prev.map((item) => (item.domain === updated.domain ? updated : item)));
    } catch (err) {
      setError('Failed to update domain');
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
                <th>Proxied</th>
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
