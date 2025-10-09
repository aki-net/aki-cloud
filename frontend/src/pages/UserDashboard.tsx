import { FormEvent, KeyboardEvent, useEffect, useRef, useState } from "react";
import {
  bulkCreateDomains,
  bulkUpdateDomains,
  deleteDomain,
  fetchDomains,
  updateDomain,
} from "../services/api";
import {
  BulkDomainResponse,
  DomainRecord,
  DomainTLSPayload,
  EncryptionMode,
} from "../types";
import { useAuth } from "../providers/AuthProvider";

type ModeChoice = "auto" | EncryptionMode;
type BulkProxyChoice = "keep" | "on" | "off";
type BulkTLSChoice = "keep" | ModeChoice;

const TLS_MODE_OPTIONS: { value: ModeChoice; label: string }[] = [
  { value: "auto", label: "Auto (Recommended)" },
  { value: "off", label: "Off" },
  { value: "flexible", label: "Flexible" },
  { value: "full", label: "Full" },
  { value: "full_strict", label: "Full (Strict)" },
  { value: "strict_origin_pull", label: "Strict (Origin Pull)" },
];

const BULK_PROXY_OPTIONS: { value: BulkProxyChoice; label: string }[] = [
  { value: "keep", label: "Keep proxy setting" },
  { value: "on", label: "Force proxied" },
  { value: "off", label: "Set DNS only" },
];

const BULK_TLS_OPTIONS: { value: BulkTLSChoice; label: string }[] = [
  { value: "keep", label: "Keep TLS mode" },
  ...TLS_MODE_OPTIONS.map((option) => ({
    value: option.value as BulkTLSChoice,
    label: option.label,
  })),
];

const MAX_BULK_DOMAINS = 1000;

const parseDomainsInput = (value: string): string[] =>
  value
    .split(/[\s,;]+/)
    .map((part) => part.trim().toLowerCase())
    .filter(Boolean);

const sortDomains = (records: DomainRecord[]): DomainRecord[] =>
  [...records].sort((a, b) => a.domain.localeCompare(b.domain));

export const UserDashboard = () => {
  const { user } = useAuth();
  const [domains, setDomains] = useState<DomainRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [originEditor, setOriginEditor] = useState<{
    domain: string;
    value: string;
    error?: string;
  } | null>(null);
  const [originSavingDomain, setOriginSavingDomain] = useState<string | null>(
    null,
  );
  const originInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!originEditor) {
      originInputRef.current = null;
      return;
    }
    const handle = window.requestAnimationFrame(() => {
      if (originInputRef.current) {
        const input = originInputRef.current;
        input.focus();
        const len = input.value.length;
        try {
          input.setSelectionRange(len, len);
        } catch {
          /* ignore selection errors */
        }
      }
    });
    return () => {
      window.cancelAnimationFrame(handle);
    };
  }, [originEditor]);

  const [bulkForm, setBulkForm] = useState({
    domains: "",
    origin_ip: "",
    proxied: true,
    ttl: 60,
    tlsMode: "auto" as ModeChoice,
  });
  const [bulkUpdate, setBulkUpdate] = useState({
    origin_ip: "",
    ttl: "",
    proxied: "keep" as BulkProxyChoice,
    tlsMode: "keep" as BulkTLSChoice,
  });

  const [bulkCreateLoading, setBulkCreateLoading] = useState(false);
  const [bulkUpdateLoading, setBulkUpdateLoading] = useState(false);

  const resetAlerts = () => {
    setError(null);
    setNotice(null);
  };

  const buildTLSPayload = (choice: ModeChoice): DomainTLSPayload =>
    choice === "auto"
      ? { use_recommended: true }
      : { use_recommended: false, mode: choice };

  const tlsPayloadForRecord = (record: DomainRecord): DomainTLSPayload =>
    record.tls.use_recommended
      ? { use_recommended: true }
      : {
          use_recommended: false,
          mode: (record.tls.mode as EncryptionMode) || "flexible",
        };

  const effectiveMode = (record: DomainRecord): ModeChoice =>
    record.tls.use_recommended
      ? "auto"
      : (record.tls.mode as EncryptionMode) || "flexible";

  const statusBadge = (status: string): string => {
    switch (status) {
      case "active":
        return "success";
      case "pending":
        return "info";
      case "errored":
        return "danger";
      case "awaiting_dns":
        return "warning";
      default:
        return "secondary";
    }
  };

  const modeLabel = (value: ModeChoice): string =>
    TLS_MODE_OPTIONS.find((option) => option.value === value)?.label ?? value;

  const load = async () => {
    setLoading(true);
    try {
      const data = await fetchDomains();
      setDomains(sortDomains(data));
      setSelected(new Set());
    } catch (err) {
      setError("Failed to load domains");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load().catch(() => null);
  }, []);

  const allSelected = domains.length > 0 && selected.size === domains.length;
  const anySelected = selected.size > 0;

  const toggleDomainSelection = (domain: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(domain)) {
        next.delete(domain);
      } else {
        next.add(domain);
      }
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (allSelected) {
      setSelected(new Set());
      return;
    }
    setSelected(new Set(domains.map((record) => record.domain)));
  };

  const applyBulkResponse = (
    response: BulkDomainResponse,
    verb: "Created" | "Updated",
  ) => {
    const updatedRecords = response.results
      .filter((entry) => entry.record)
      .map((entry) => entry.record!) as DomainRecord[];
    if (updatedRecords.length > 0) {
      setDomains((prev) => {
        const map = new Map(prev.map((item) => [item.domain, item]));
        updatedRecords.forEach((record) => map.set(record.domain, record));
        return sortDomains(Array.from(map.values()));
      });
    }

    const parts: string[] = [];
    parts.push(
      response.success > 0
        ? `${verb} ${response.success} domain${response.success === 1 ? "" : "s"}`
        : `No domains ${verb.toLowerCase()}`,
    );
    if (response.skipped > 0) {
      parts.push(`Skipped ${response.skipped}`);
    }
    setNotice(parts.join(". "));

    const failed = response.results.filter(
      (entry) => entry.status === "failed",
    );
    if (failed.length > 0) {
      const details = failed
        .map((entry) =>
          entry.error ? `${entry.domain} (${entry.error})` : entry.domain,
        )
        .join(", ");
      setError(`Failed: ${details}`);
    } else {
      setError(null);
    }

    setSelected(new Set());
  };

  const toggleProxied = async (record: DomainRecord) => {
    resetAlerts();
    try {
      const updated = await updateDomain(record.domain, {
        origin_ip: record.origin_ip,
        proxied: !record.proxied,
        ttl: record.ttl,
        tls: tlsPayloadForRecord(record),
      });
      setDomains((prev) =>
        sortDomains(
          prev.map((item) => (item.domain === updated.domain ? updated : item)),
        ),
      );
      setNotice(
        `Proxy ${updated.proxied ? "enabled" : "disabled"} for ${updated.domain}`,
      );
    } catch (err) {
      setError("Failed to update domain");
    }
  };

  const updateTLSMode = async (record: DomainRecord, choice: ModeChoice) => {
    resetAlerts();
    try {
      const updated = await updateDomain(record.domain, {
        origin_ip: record.origin_ip,
        proxied: record.proxied,
        ttl: record.ttl,
        tls: buildTLSPayload(choice),
      });
      setDomains((prev) =>
        sortDomains(
          prev.map((item) => (item.domain === updated.domain ? updated : item)),
        ),
      );
      setNotice(`TLS mode updated for ${record.domain}`);
    } catch (err) {
      setError("Failed to update TLS mode");
    }
  };

  const onDelete = async (record: DomainRecord) => {
    if (!window.confirm(`Delete ${record.domain}?`)) {
      return;
    }
    resetAlerts();
    try {
      await deleteDomain(record.domain);
      setDomains((prev) => prev.filter((d) => d.domain !== record.domain));
      setSelected((prev) => {
        const next = new Set(prev);
        next.delete(record.domain);
        return next;
      });
      setNotice(`Removed ${record.domain}`);
    } catch (err) {
      setError("Failed to delete domain");
    }
  };

  const beginOriginEdit = (record: DomainRecord) => {
    setOriginEditor({ domain: record.domain, value: record.origin_ip });
  };

  const cancelOriginEdit = () => {
    setOriginEditor(null);
  };

  const handleOriginChange = (value: string) => {
    setOriginEditor((prev) =>
      prev ? { ...prev, value, error: undefined } : prev,
    );
  };

  const validateIPv4 = (value: string): string | null => {
    const trimmed = value.trim();
    if (!trimmed) {
      return "Origin IP is required";
    }
    const ipv4Pattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Pattern.test(trimmed)) {
      return "Enter a valid IPv4 address";
    }
    const invalidOctet = trimmed.split(".").some((part) => {
      const num = Number(part);
      return Number.isNaN(num) || num > 255;
    });
    if (invalidOctet) {
      return "Each octet must be between 0 and 255";
    }
    return null;
  };

  const saveOrigin = async (record: DomainRecord) => {
    if (!originEditor || originEditor.domain !== record.domain) {
      return;
    }
    const validationError = validateIPv4(originEditor.value);
    if (validationError) {
      setOriginEditor((prev) =>
        prev ? { ...prev, error: validationError } : prev,
      );
      return;
    }

    const trimmed = originEditor.value.trim();
    resetAlerts();
    setOriginSavingDomain(record.domain);
    try {
      const tlsPayload =
        record.proxied === false
          ? { use_recommended: false, mode: "off" as EncryptionMode }
          : tlsPayloadForRecord(record);

      const updated = await updateDomain(record.domain, {
        origin_ip: trimmed,
        proxied: record.proxied,
        ttl: record.ttl,
        tls: tlsPayload,
      });
      setDomains((prev) =>
        sortDomains(
          prev.map((item) => (item.domain === updated.domain ? updated : item)),
        ),
      );
      setNotice(`Origin updated for ${updated.domain}`);
      setOriginEditor(null);
    } catch (err) {
      setError("Failed to update origin IP");
    } finally {
      setOriginSavingDomain(null);
    }
  };

  const onOriginKeyDown = (
    event: KeyboardEvent<HTMLInputElement>,
    record: DomainRecord,
  ) => {
    if (event.key === "Enter") {
      event.preventDefault();
      void saveOrigin(record);
    } else if (event.key === "Escape") {
      event.preventDefault();
      cancelOriginEdit();
    }
  };

  const onBulkCreate = async (event: FormEvent) => {
    event.preventDefault();
    resetAlerts();

    const domainsList = parseDomainsInput(bulkForm.domains);
    if (domainsList.length === 0) {
      setError("Provide at least one domain");
      return;
    }
    if (domainsList.length > MAX_BULK_DOMAINS) {
      setError(
        `You can add up to ${MAX_BULK_DOMAINS} domains in one bulk request`,
      );
      return;
    }
    if (!bulkForm.origin_ip.trim()) {
      setError("Origin IP is required");
      return;
    }
    if (!bulkForm.proxied && bulkForm.tlsMode !== "off") {
      setError("TLS must be set to Off for DNS-only domains");
      return;
    }

    setBulkCreateLoading(true);
    try {
      const payload = {
        domains: domainsList,
        origin_ip: bulkForm.origin_ip.trim(),
        owner: user?.id,
        proxied: bulkForm.proxied,
        ttl: bulkForm.ttl,
        tls: buildTLSPayload(bulkForm.proxied ? bulkForm.tlsMode : "off"),
      };
      const response = await bulkCreateDomains(payload);
      applyBulkResponse(response, "Created");
      if (response.success > 0) {
        setBulkForm((prev) => ({ ...prev, domains: "" }));
      }
    } catch (err) {
      setError("Bulk create failed");
    } finally {
      setBulkCreateLoading(false);
    }
  };

  const onBulkUpdate = async (event: FormEvent) => {
    event.preventDefault();
    resetAlerts();
    if (!anySelected) {
      setError("Select at least one domain to update");
      return;
    }
    const payload: {
      domains: string[];
      origin_ip?: string;
      proxied?: boolean;
      ttl?: number;
      tls?: DomainTLSPayload;
    } = {
      domains: Array.from(selected),
    };
    let hasChange = false;

    if (bulkUpdate.origin_ip.trim()) {
      payload.origin_ip = bulkUpdate.origin_ip.trim();
      hasChange = true;
    }
    if (bulkUpdate.ttl.trim()) {
      const ttlValue = Number(bulkUpdate.ttl);
      if (!Number.isFinite(ttlValue) || ttlValue <= 0) {
        setError("TTL must be a positive number");
        return;
      }
      payload.ttl = ttlValue;
      hasChange = true;
    }
    if (bulkUpdate.proxied !== "keep") {
      payload.proxied = bulkUpdate.proxied === "on";
      hasChange = true;
    }
    if (bulkUpdate.tlsMode !== "keep") {
      payload.tls = buildTLSPayload(bulkUpdate.tlsMode as ModeChoice);
      hasChange = true;
    }

    if (!hasChange) {
      setError("Choose at least one field to update");
      return;
    }
    if (
      payload.proxied === false &&
      payload.tls?.mode &&
      payload.tls.mode !== "off"
    ) {
      setError("TLS must be off when disabling proxying");
      return;
    }

    setBulkUpdateLoading(true);
    try {
      const response = await bulkUpdateDomains(payload);
      applyBulkResponse(response, "Updated");
    } catch (err) {
      setError("Bulk update failed");
    } finally {
      setBulkUpdateLoading(false);
    }
  };

  return (
    <div className="grid">
      <div className="card">
        <h2 className="section-title">Your Domains</h2>
        <p className="alert">
          Changes may take up to 20 seconds to synchronize across edge nodes.
        </p>
        {notice && <div className="alert success">{notice}</div>}
        {error && <div className="alert">{error}</div>}
        <div className="text-muted">
          Selected {selected.size} of {domains.length}
        </div>
        {loading ? (
          <p>Loading…</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    checked={allSelected}
                    onChange={toggleSelectAll}
                  />
                </th>
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
                  <td>
                    <input
                      type="checkbox"
                      checked={selected.has(record.domain)}
                      onChange={() => toggleDomainSelection(record.domain)}
                    />
                  </td>
                  <td>{record.domain}</td>
                  <td>
                    {originEditor?.domain === record.domain ? (
                      <form
                        className="inline-edit"
                        onSubmit={(event) => {
                          event.preventDefault();
                          void saveOrigin(record);
                        }}
                      >
                        <input
                          className="input"
                          value={originEditor.value}
                          onChange={(event) =>
                            handleOriginChange(event.target.value)
                          }
                          onKeyDown={(event) => onOriginKeyDown(event, record)}
                          disabled={originSavingDomain === record.domain}
                          ref={(element) => {
                            if (originEditor?.domain === record.domain) {
                              originInputRef.current = element;
                            }
                          }}
                        />
                        <button
                          className="button secondary"
                          type="button"
                          disabled={originSavingDomain === record.domain}
                          onClick={() => void saveOrigin(record)}
                          style={{ marginLeft: "0.5rem" }}
                        >
                          Save
                        </button>
                        <button
                          className="button secondary"
                          type="button"
                          disabled={originSavingDomain === record.domain}
                          onClick={cancelOriginEdit}
                          style={{ marginLeft: "0.25rem" }}
                        >
                          Cancel
                        </button>
                        {originEditor.error && (
                          <div className="text-muted">{originEditor.error}</div>
                        )}
                      </form>
                    ) : (
                      <span
                        role="button"
                        tabIndex={0}
                        className="origin-edit-trigger"
                        title="Click to edit origin IP"
                        style={{ cursor: "pointer" }}
                        onClick={() => beginOriginEdit(record)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            beginOriginEdit(record);
                          }
                        }}
                      >
                        {record.origin_ip}
                      </span>
                    )}
                  </td>
                  <td>
                    <button
                      className="button secondary"
                      onClick={() => toggleProxied(record)}
                    >
                      {record.proxied ? "Proxied" : "DNS Only"}
                    </button>
                  </td>
                  <td>
                    <select
                      className="input"
                      value={effectiveMode(record)}
                      disabled={!record.proxied}
                      onChange={(e) =>
                        updateTLSMode(record, e.target.value as ModeChoice)
                      }
                    >
                      {TLS_MODE_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <span className={`badge ${statusBadge(record.tls.status)}`}>
                      {record.tls.status}
                    </span>
                    {record.tls.status === "awaiting_dns" && (
                      <div className="text-muted">Awaiting DNS delegation</div>
                    )}
                    {!record.proxied && (
                      <div className="text-muted">
                        TLS automation paused (DNS only)
                      </div>
                    )}
                    {record.tls.certificate?.not_after && (
                      <div className="text-muted">
                        exp.{" "}
                        {new Date(
                          record.tls.certificate.not_after,
                        ).toLocaleDateString()}
                      </div>
                    )}
                    {record.tls.use_recommended &&
                      record.tls.recommended_mode && (
                        <div className="text-muted">
                          auto →{" "}
                          {modeLabel(record.tls.recommended_mode as ModeChoice)}
                        </div>
                      )}
                    {record.tls.last_error && (
                      <div className="text-muted">{record.tls.last_error}</div>
                    )}
                    {record.tls.origin_pull_secret?.ca_pem && (
                      <details>
                        <summary>Origin Pull CA</summary>
                        <pre className="code-block">
                          {record.tls.origin_pull_secret.ca_pem}
                        </pre>
                      </details>
                    )}
                    {record.tls.origin_pull_secret?.certificate_pem && (
                      <details>
                        <summary>Edge Client Cert</summary>
                        <pre className="code-block">
                          {record.tls.origin_pull_secret.certificate_pem}
                        </pre>
                      </details>
                    )}
                    {record.tls.origin_pull_secret?.fingerprint && (
                      <div className="text-muted">
                        fingerprint {record.tls.origin_pull_secret.fingerprint}
                      </div>
                    )}
                  </td>
                  <td>{record.ttl}s</td>
                  <td>{new Date(record.updated_at).toLocaleString()}</td>
                  <td>
                    <button
                      className="button secondary"
                      onClick={() => onDelete(record)}
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <form className="card" onSubmit={onBulkUpdate}>
        <h3 className="section-title">Bulk Update Selected Domains</h3>
        <p className="text-muted">
          Select domains above, then choose the settings to override.
        </p>
        <label>
          Origin IP (optional)
          <input
            className="input"
            placeholder="203.0.113.10"
            value={bulkUpdate.origin_ip}
            onChange={(e) =>
              setBulkUpdate((prev) => ({ ...prev, origin_ip: e.target.value }))
            }
          />
        </label>
        <label>
          TTL seconds (optional)
          <input
            className="input"
            type="number"
            min={30}
            value={bulkUpdate.ttl}
            onChange={(e) =>
              setBulkUpdate((prev) => ({ ...prev, ttl: e.target.value }))
            }
          />
        </label>
        <label>
          Proxy behaviour
          <select
            className="input"
            value={bulkUpdate.proxied}
            onChange={(e) => {
              const choice = e.target.value as BulkProxyChoice;
              setBulkUpdate((prev) => ({
                ...prev,
                proxied: choice,
                tlsMode: choice === "off" ? "keep" : prev.tlsMode,
              }));
            }}
          >
            {BULK_PROXY_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          TLS mode
          <select
            className="input"
            value={bulkUpdate.tlsMode}
            disabled={bulkUpdate.proxied === "off"}
            onChange={(e) =>
              setBulkUpdate((prev) => ({
                ...prev,
                tlsMode: e.target.value as BulkTLSChoice,
              }))
            }
          >
            {BULK_TLS_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <button
          className="button"
          type="submit"
          disabled={!anySelected || bulkUpdateLoading}
        >
          {bulkUpdateLoading ? "Applying…" : "Apply to selected"}
        </button>
      </form>

      <form className="card" onSubmit={onBulkCreate}>
        <h3 className="section-title">Bulk Add Domains</h3>
        <p className="text-muted">
          Paste up to {MAX_BULK_DOMAINS} domains separated by spaces, commas, or
          new lines.
        </p>
        <label>
          Domains
          <textarea
            className="input"
            rows={6}
            placeholder="example.com&#10;example.net"
            value={bulkForm.domains}
            onChange={(e) =>
              setBulkForm((prev) => ({ ...prev, domains: e.target.value }))
            }
            required
          />
        </label>
        <label>
          Origin IP
          <input
            className="input"
            placeholder="203.0.113.10"
            value={bulkForm.origin_ip}
            onChange={(e) =>
              setBulkForm((prev) => ({ ...prev, origin_ip: e.target.value }))
            }
            required
          />
        </label>
        <label>
          TTL seconds
          <input
            className="input"
            type="number"
            min={30}
            value={bulkForm.ttl}
            onChange={(e) =>
              setBulkForm((prev) => ({ ...prev, ttl: Number(e.target.value) }))
            }
          />
        </label>
        <label>
          Edge TLS mode
          <select
            className="input"
            value={bulkForm.tlsMode}
            disabled={!bulkForm.proxied}
            onChange={(e) =>
              setBulkForm((prev) => ({
                ...prev,
                tlsMode: e.target.value as ModeChoice,
              }))
            }
          >
            {TLS_MODE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="flex">
          <input
            type="checkbox"
            checked={bulkForm.proxied}
            onChange={(e) =>
              setBulkForm((prev) => ({
                ...prev,
                proxied: e.target.checked,
                tlsMode: e.target.checked
                  ? prev.tlsMode === "off"
                    ? "auto"
                    : prev.tlsMode
                  : "off",
              }))
            }
          />
          Proxy through edge network
        </label>
        <button className="button" type="submit" disabled={bulkCreateLoading}>
          {bulkCreateLoading ? "Creating…" : "Create domains"}
        </button>
      </form>
    </div>
  );
};
