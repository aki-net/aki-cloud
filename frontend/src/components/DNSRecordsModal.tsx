import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { domains as domainsApi } from "../api/client";
import {
  Domain,
  DomainDNSRecord,
  DNSRecordType,
  CreateDNSRecordPayload,
  UpdateDNSRecordPayload,
} from "../types";
import Button from "./ui/Button";
import Input from "./ui/Input";
import Switch from "./ui/Switch";
import Badge from "./ui/Badge";
import toast from "react-hot-toast";

interface DNSRecordsModalProps {
  domain: Domain;
  onClose: () => void;
  onChange?: () => void;
}

type RecordFormState = {
  id?: string;
  type: DNSRecordType;
  name: string;
  content: string;
  ttl: string;
  priority: string;
  proxied: boolean;
  comment: string;
};

type RecordTypeMeta = {
  value: DNSRecordType;
  label: string;
  description: string;
  proxyable: boolean;
  requiresPriority?: boolean;
};

const RECORD_TYPES: RecordTypeMeta[] = [
  { value: "A", label: "A (IPv4 address)", description: "Points to an IPv4 address.", proxyable: true },
  { value: "AAAA", label: "AAAA (IPv6 address)", description: "Points to an IPv6 address.", proxyable: true },
  { value: "CAA", label: "CAA", description: "Controls which CAs can issue certificates.", proxyable: false },
  { value: "CERT", label: "CERT", description: "Stores PKIX, SPKI, PGP, or other certificates.", proxyable: false },
  { value: "CNAME", label: "CNAME (Alias)", description: "Points one name to another hostname.", proxyable: true },
  { value: "DNSKEY", label: "DNSKEY", description: "Holds a DNSSEC public key.", proxyable: false },
  { value: "DS", label: "DS", description: "Delegation signer record for DNSSEC.", proxyable: false },
  { value: "HTTPS", label: "HTTPS", description: "Provides HTTPS endpoint hints.", proxyable: false },
  { value: "LOC", label: "LOC", description: "Specifies geographical location information.", proxyable: false },
  { value: "MX", label: "MX (Mail exchange)", description: "Directs mail to a mail server.", proxyable: false, requiresPriority: true },
  { value: "NAPTR", label: "NAPTR", description: "Regex-based rewriting of domain names.", proxyable: false },
  { value: "NS", label: "NS", description: "Delegates a DNS zone to authoritative name servers.", proxyable: false },
  { value: "OPENPGPKEY", label: "OPENPGPKEY", description: "Publishes an OpenPGP public key.", proxyable: false },
  { value: "PTR", label: "PTR", description: "Maps an IP address to a hostname.", proxyable: false },
  { value: "SMIMEA", label: "SMIMEA", description: "Binds S/MIME certificates to email addresses.", proxyable: false },
  { value: "SRV", label: "SRV", description: "Specifies a service location.", proxyable: false, requiresPriority: true },
  { value: "SSHFP", label: "SSHFP", description: "Stores SSH public key fingerprints.", proxyable: false },
  { value: "SVCB", label: "SVCB", description: "Service binding record for advanced services.", proxyable: false },
  { value: "TLSA", label: "TLSA", description: "Associates TLS server certificates or public keys.", proxyable: false },
  { value: "TXT", label: "TXT", description: "Arbitrary text for SPF, DKIM, verification, etc.", proxyable: false },
  { value: "URI", label: "URI", description: "Maps hostnames to URIs.", proxyable: false },
];

const PROXYABLE_TYPES = new Set<DNSRecordType>(["A", "AAAA", "CNAME"]);

const CONTENT_PLACEHOLDERS: Partial<Record<DNSRecordType, string>> = {
  A: "IPv4 address or @ to reuse root",
  AAAA: "IPv6 address",
  CNAME: "Hostname or @ for root domain",
  MX: "Mail server hostname",
  TXT: "v=spf1 include:example.com ~all",
  SRV: "Target host",
  URI: "https://example.com/service",
  HTTPS: "svc.example.com",
  SVCB: "svc.example.com",
};

const isApexRecord = (record: DomainDNSRecord): boolean => {
  const name = record.name?.trim().toLowerCase() ?? "";
  return record.type === "A" && (name === "" || name === "@");
};

const getTypeMeta = (value: DNSRecordType): RecordTypeMeta =>
  RECORD_TYPES.find((item) => item.value === value) ?? RECORD_TYPES[0];

const createDefaultFormState = (domain: Domain): RecordFormState => ({
  type: "A",
  name: "@",
  content: "",
  ttl: "",
  priority: "",
  proxied: domain.proxied,
  comment: "",
});

const normalizeName = (value: string) => value.trim() || "@";
const normalizeContent = (value: string) => value.trim();

const parsePositiveInteger = (value: string): number | undefined | null => {
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }
  const parsed = Number(trimmed);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return null;
  }
  return Math.floor(parsed);
};

export default function DNSRecordsModal({
  domain,
  onClose,
  onChange,
}: DNSRecordsModalProps) {
  const modalRef = useRef<HTMLDivElement>(null);
  const [isMouseDownOutside, setIsMouseDownOutside] = useState(false);
  const [records, setRecords] = useState<DomainDNSRecord[]>(
    () => domain.dns_records ?? [],
  );
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formState, setFormState] = useState<RecordFormState>(() =>
    createDefaultFormState(domain),
  );

  const domainSupportsProxy = domain.proxied;

  const currentTypeMeta = useMemo(
    () => getTypeMeta(formState.type),
    [formState.type],
  );

  const hasApexRecord = useMemo(
    () => records.some(isApexRecord),
    [records],
  );

  const fetchRecords = useCallback(async () => {
    setLoading(true);
    try {
      const list = await domainsApi.dnsRecords.list(domain.domain);
      const sorted = [...list].sort((a, b) => {
        const nameA = (a.name || "@").toLowerCase();
        const nameB = (b.name || "@").toLowerCase();
        if (nameA !== nameB) {
          return nameA.localeCompare(nameB);
        }
        return a.type.localeCompare(b.type);
      });
      setRecords(sorted);
    } catch (error: any) {
      toast.error(
        error?.response?.data?.error || "Failed to load DNS records",
      );
    } finally {
      setLoading(false);
    }
  }, [domain.domain]);

  useEffect(() => {
    setFormState(createDefaultFormState(domain));
    setEditingId(null);
    if (Array.isArray(domain.dns_records)) {
      setRecords(domain.dns_records);
    }
  }, [domain.domain]);

  useEffect(() => {
    fetchRecords();
  }, [fetchRecords]);

  const handleOverlayMouseDown = (event: React.MouseEvent<HTMLDivElement>) => {
    if (
      modalRef.current &&
      !modalRef.current.contains(event.target as Node)
    ) {
      setIsMouseDownOutside(true);
    }
  };

  const handleOverlayMouseUp = (event: React.MouseEvent<HTMLDivElement>) => {
    if (
      isMouseDownOutside &&
      modalRef.current &&
      !modalRef.current.contains(event.target as Node)
    ) {
      onClose();
    }
    setIsMouseDownOutside(false);
  };

  const resetForm = () => {
    setFormState(createDefaultFormState(domain));
    setEditingId(null);
  };

  const handleEdit = (record: DomainDNSRecord) => {
    setEditingId(record.id);
    setFormState({
      id: record.id,
      type: record.type,
      name: record.name === "" ? "@" : record.name,
      content: record.content,
      ttl: record.ttl > 0 ? String(record.ttl) : "",
      priority:
        typeof record.priority === "number" && !Number.isNaN(record.priority)
          ? String(record.priority)
          : "",
      proxied: domainSupportsProxy && PROXYABLE_TYPES.has(record.type)
        ? record.proxied
        : false,
      comment: record.comment ?? "",
    });
  };

  const handleDelete = async (record: DomainDNSRecord) => {
    if (
      !window.confirm(
        `Delete ${record.type} record ${record.name || "@"}? This cannot be undone.`,
      )
    ) {
      return;
    }
    setDeletingId(record.id);
    try {
      await domainsApi.dnsRecords.delete(domain.domain, record.id);
      toast.success("DNS record removed");
      await fetchRecords();
      onChange?.();
      if (editingId === record.id) {
        resetForm();
      }
    } catch (error: any) {
      toast.error(
        error?.response?.data?.error || "Failed to delete DNS record",
      );
    } finally {
      setDeletingId(null);
    }
  };

  const handleFormSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const name = normalizeName(formState.name);
    const content = normalizeContent(formState.content);

    if (!content && PROXYABLE_TYPES.has(formState.type)) {
      // For proxied records without explicit content we allow empty values (will flatten to edge IP)
    } else if (!content) {
      toast.error("Record content is required");
      return;
    }

    const ttlValue = parsePositiveInteger(formState.ttl);
    if (ttlValue === null) {
      toast.error("TTL must be a positive number");
      return;
    }

    let priorityValue = parsePositiveInteger(formState.priority);
    if (currentTypeMeta.requiresPriority) {
      if (priorityValue === undefined || priorityValue === null) {
        toast.error("Priority is required for this record type");
        return;
      }
    } else if (priorityValue === null) {
      toast.error("Priority must be a positive number");
      return;
    }

    const proxiedAllowed =
      domainSupportsProxy && PROXYABLE_TYPES.has(formState.type);

    const commentValue = formState.comment.trim();

    const payloadBase: CreateDNSRecordPayload = {
      name,
      type: formState.type,
      content,
    };
    if (ttlValue !== undefined) {
      payloadBase.ttl = ttlValue;
    }
    if (priorityValue !== undefined) {
      payloadBase.priority = priorityValue;
    }
    payloadBase.proxied = proxiedAllowed ? formState.proxied : false;
    if (commentValue) {
      payloadBase.comment = commentValue;
    }

    setSaving(true);
    try {
      if (editingId) {
        const updatePayload: UpdateDNSRecordPayload = payloadBase;
        await domainsApi.dnsRecords.update(
          domain.domain,
          editingId,
          updatePayload,
        );
        toast.success("DNS record updated");
      } else {
        await domainsApi.dnsRecords.create(domain.domain, payloadBase);
        toast.success("DNS record added");
      }
      await fetchRecords();
      onChange?.();
      resetForm();
    } catch (error: any) {
      toast.error(
        error?.response?.data?.error || "Failed to save DNS record",
      );
    } finally {
      setSaving(false);
    }
  };

  const handleTypeChange = (value: DNSRecordType) => {
    const meta = getTypeMeta(value);
    setFormState((prev) => ({
      ...prev,
      type: value,
      proxied: meta.proxyable && domainSupportsProxy ? prev.proxied : false,
      priority:
        meta.requiresPriority || value === "MX" || value === "SRV"
          ? prev.priority
          : "",
    }));
  };

  return (
    <div
      className="modal-overlay"
      onMouseDown={handleOverlayMouseDown}
      onMouseUp={handleOverlayMouseUp}
    >
      <div className="modal dns-records-modal" ref={modalRef}>
        <header className="modal-header">
          <h2>DNS records for {domain.domain}</h2>
          <button type="button" className="modal-close" onClick={onClose}>
            ×
          </button>
        </header>
        <div className="modal-body">
          <section className="modal-section dns-records-summary">
            <div className="dns-records-summary-meta">
              <Badge variant={domainSupportsProxy ? "success" : "neutral"}>
                {domainSupportsProxy ? "Proxy enabled" : "DNS only"}
              </Badge>
              <span className="dns-records-count">
                {records.length} record{records.length === 1 ? "" : "s"}
              </span>
            </div>
            <div className="dns-records-summary-text">
              {hasApexRecord ? (
                <p>
                  Root traffic resolves via your <code>@</code> A record. Adjust content below to change the origin.
                </p>
              ) : (
                <p>
                  No apex <code>@</code> A record is published. Visitors will see the aki.cloud placeholder until you add one.
                </p>
              )}
              <p className="dns-records-summary-hint">
                Only A, AAAA, and CNAME records support proxying. All other types stay DNS-only by design.
              </p>
            </div>
          </section>
          <section className="modal-section">
            <div className="section-header">
              <h3>Existing records</h3>
              <Button
                size="sm"
                variant="secondary"
                onClick={resetForm}
                disabled={saving}
              >
                New record
              </Button>
            </div>
            {loading ? (
              <div className="dns-records-empty">Loading records…</div>
            ) : records.length === 0 ? (
              <div className="dns-records-empty">
                No records yet. Create one below to get started.
              </div>
            ) : (
              <div className="dns-records-table-wrapper">
                <table className="dns-records-table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Name</th>
                      <th>Content</th>
                      <th>Proxy</th>
                      <th className="dns-records-actions-header">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {records.map((record) => (
                      <tr key={record.id}>
                        <td>{record.type}</td>
                        <td>{record.name || "@"}</td>
                        <td className="dns-records-content">{record.content || "—"}</td>
                        <td>
                          {record.proxied ? (
                            <Badge variant="success">Proxied</Badge>
                          ) : (
                            <Badge variant="neutral">DNS only</Badge>
                          )}
                        </td>
                        <td>
                          <button
                            type="button"
                            className="dns-record-edit"
                            onClick={() => handleEdit(record)}
                            disabled={saving || deletingId === record.id}
                          >
                            Edit
                          </button>
                          <button
                            type="button"
                            className="dns-record-delete"
                            onClick={() => handleDelete(record)}
                            disabled={saving || deletingId === record.id}
                          >
                            {deletingId === record.id ? "Removing…" : "Delete"}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
          <section className="modal-section">
            <form className="dns-records-form" onSubmit={handleFormSubmit}>
              <div className="dns-records-row">
                <label className="dns-field-type">
                  Type
                  <select
                    className="dns-type-select"
                    value={formState.type}
                    onChange={(e) => handleTypeChange(e.target.value as DNSRecordType)}
                  >
                    {RECORD_TYPES.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </label>
                <div className="dns-records-proxy-toggle">
                  <span className="dns-proxy-label">Proxy traffic</span>
                  <Switch
                    checked={formState.proxied && domainSupportsProxy}
                    onChange={(value) =>
                      setFormState((prev) => ({
                        ...prev,
                        proxied: value,
                      }))
                    }
                    disabled={!currentTypeMeta.proxyable || !domainSupportsProxy}
                    size="sm"
                    title={
                      !domainSupportsProxy
                        ? "Enable proxy for the domain to route traffic through the edge"
                        : !currentTypeMeta.proxyable
                          ? "This DNS record type cannot be proxied"
                          : "Toggle edge protection for this record"
                    }
                  />
                  {!domainSupportsProxy && (
                    <span className="dns-records-hint">
                      Enable proxying on the domain to activate edge protection.
                    </span>
                  )}
                  {domainSupportsProxy && !currentTypeMeta.proxyable && (
                    <span className="dns-records-hint">
                      This record type cannot be proxied.
                    </span>
                  )}
                </div>
              </div>
              <div className="dns-records-row dns-records-row-inputs">
                <label className="dns-field-name">
                  Name
                  <Input
                    value={formState.name}
                    onChange={(e) =>
                      setFormState((prev) => ({ ...prev, name: e.target.value }))
                    }
                    placeholder="@ (root) or subdomain"
                  />
                </label>
                <label className="dns-field-content">
                  Content
                  <Input
                    value={formState.content}
                    onChange={(e) =>
                      setFormState((prev) => ({
                        ...prev,
                        content: e.target.value,
                      }))
                    }
                    placeholder={
                      CONTENT_PLACEHOLDERS[formState.type] ??
                      (currentTypeMeta.proxyable ? "IP or hostname" : "Record value")
                    }
                  />
                </label>
              </div>
              <p className="dns-records-description">
                {currentTypeMeta.description}
              </p>
              <div className="modal-actions">
                {editingId ? (
                  <Button
                    type="button"
                    variant="ghost"
                    onClick={resetForm}
                    disabled={saving}
                  >
                    Cancel edit
                  </Button>
                ) : (
                  <Button
                    type="button"
                    variant="ghost"
                    onClick={onClose}
                    disabled={saving}
                  >
                    Close
                  </Button>
                )}
                <Button type="submit" variant="primary" loading={saving}>
                  {editingId ? "Save changes" : "Add record"}
                </Button>
              </div>
            </form>
          </section>
        </div>
      </div>
    </div>
  );
}
