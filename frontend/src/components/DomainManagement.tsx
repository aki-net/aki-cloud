import React, { useState, useEffect, useRef } from "react";
import { domains as domainsApi, infra, admin } from "../api/client";
import {
  Domain,
  CreateDomainPayload,
  NameServerEntry,
  DomainOverview,
  EdgeEndpoint,
} from "../types";
import Table from "./ui/Table";
import Button from "./ui/Button";
import Input from "./ui/Input";
import Switch from "./ui/Switch";
import Badge from "./ui/Badge";
import Card from "./ui/Card";
import PageHeader from "./PageHeader";
import toast from "react-hot-toast";
import { format, formatDistanceToNow } from "date-fns";
import { useAuth } from "../contexts/AuthContext";
import "./DomainManagement.css";

interface Props {
  isAdmin?: boolean;
}

export default function DomainManagement({ isAdmin = false }: Props) {
  const { user } = useAuth();
  const [domains, setDomains] = useState<Domain[]>([]);
  const [allDomains, setAllDomains] = useState<DomainOverview[]>([]);
  const [nameservers, setNameservers] = useState<NameServerEntry[]>([]);
  const [edgeEndpoints, setEdgeEndpoints] = useState<EdgeEndpoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedDomains, setSelectedDomains] = useState<Set<string>>(
    new Set(),
  );
  const [showAddDomain, setShowAddDomain] = useState(false);
  const [editingDomain, setEditingDomain] = useState<string | null>(null);
  const [editingIP, setEditingIP] = useState("");
  const [viewMode, setViewMode] = useState<"my" | "all" | "orphaned">("my");
  const [bulkIP, setBulkIP] = useState("");
  const [bulkOwner, setBulkOwner] = useState("");
  const [availableLabels, setAvailableLabels] = useState<string[]>([]);
  const [labelFilter, setLabelFilter] = useState<string>("all");
  const [edgeModalData, setEdgeModalData] = useState<EdgeModalData | null>(
    null,
  );

  interface EdgeModalData {
    domain: string;
    origin_ip: string;
    proxied: boolean;
    ttl: number;
    labels: string[];
    assigned_ip?: string;
    node_name?: string;
    node_id?: string;
  }
  const editInputRef = useRef<HTMLInputElement>(null);
  const loadDataRef = useRef<() => Promise<void>>();
  const [refreshInterval, setRefreshInterval] = useState<NodeJS.Timeout | null>(null);

  useEffect(() => {
    loadData(true);
    
    // Set up automatic refresh every 5 seconds for admin, 10 seconds for users
    const interval = setInterval(() => {
      loadData(false);
    }, isAdmin ? 5000 : 10000);
    
    setRefreshInterval(interval);
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isAdmin]);

  useEffect(() => {
    loadDataRef.current = loadData;
  }, []);

  const loadData = async (showLoader = false) => {
    if (showLoader) setLoading(true);
    
    try {
      const [domainData, nsData, edgeData, overviewData] = await Promise.all([
        domainsApi.list(),
        infra.nameservers(),
        isAdmin ? infra.edges() : Promise.resolve<EdgeEndpoint[]>([]),
        isAdmin
          ? admin.domainsOverview().catch(() => [])
          : Promise.resolve<DomainOverview[]>([]),
      ]);

      setDomains(domainData);
      setNameservers(nsData);

      if (isAdmin) {
        setEdgeEndpoints(edgeData);
        setAllDomains(overviewData);

        const labelSet = new Set<string>();
        edgeData.forEach((edge) =>
          edge.labels?.forEach((label) => labelSet.add(label)),
        );
        domainData.forEach((domain) =>
          domain.edge?.labels?.forEach((label) => labelSet.add(label)),
        );
        overviewData.forEach((overview) =>
          overview.edge_labels?.forEach((label) => labelSet.add(label)),
        );
        const sortedLabels = Array.from(labelSet).sort((a, b) =>
          a.localeCompare(b),
        );
        setAvailableLabels(sortedLabels);
        if (
          labelFilter !== "all" &&
          labelFilter !== "unlabeled" &&
          !sortedLabels.includes(labelFilter)
        ) {
          setLabelFilter("all");
        }
      } else {
        setAllDomains([]);
        setEdgeEndpoints([]);
        if (availableLabels.length > 0) {
          setAvailableLabels([]);
        }
        if (labelFilter !== "all") {
          setLabelFilter("all");
        }
      }
    } catch (error) {
      // Only show error toast on initial load or user-triggered refresh
      if (showLoader) {
        toast.error("Failed to load data");
      }
    } finally {
      if (showLoader) setLoading(false);
    }
  };

  const modeLabel = (mode?: string | null) => {
    if (!mode) return "";
    switch (mode) {
      case "flexible":
        return "Flexible";
      case "full":
        return "Full";
      case "full_strict":
        return "Full (Strict)";
      case "strict_origin_pull":
        return "Strict Origin Pull";
      case "off":
        return "Off";
      default:
        return mode;
    }
  };

  const computeRetryHint = (iso?: string | null) => {
    if (!iso) return "";
    const retry = new Date(iso);
    if (Number.isNaN(retry.getTime()) || retry.getUTCFullYear() <= 1900) {
      return "";
    }
    const now = Date.now();
    if (retry.getTime() <= now) {
      return "Retrying now";
    }
    return `Retry ${formatDistanceToNow(retry, { addSuffix: true })}`;
  };

  const tlsStatusMeta: Record<
    string,
    {
      variant:
        | "default"
        | "primary"
        | "success"
        | "warning"
        | "danger"
        | "info";
      label: string;
    }
  > = {
    none: { variant: "default", label: "inactive" },
    pending: { variant: "warning", label: "pending" },
    active: { variant: "success", label: "active" },
    errored: { variant: "danger", label: "error" },
    awaiting_dns: { variant: "info", label: "awaiting dns" },
  };

  const renderStatusIndicator = (
    statusKey: string,
    error?: string,
    retryHint?: string,
  ) => {
    const meta = tlsStatusMeta[statusKey] || tlsStatusMeta.none;
    return (
      <div className="tls-status-chip">
        <Badge variant={meta.variant} size="sm" dot title={error || undefined}>
          {meta.label}
        </Badge>
        {retryHint && <span className="tls-retry-hint">{retryHint}</span>}
      </div>
    );
  };

  const findFullDomain = (domainName: string) =>
    domains.find((d) => d.domain === domainName);

  const getDomainLabels = (record: Domain | DomainOverview): string[] => {
    const full = findFullDomain(record.domain);
    if (full?.edge?.labels) {
      return full.edge.labels;
    }
    if ("edge" in record) {
      return record.edge?.labels || [];
    }
    return record.edge_labels || [];
  };

  const buildEdgeModalData = (
    record: Domain | DomainOverview,
    override?: Domain,
  ): EdgeModalData => {
    const source = override ?? findFullDomain(record.domain);
    const assignedIp =
      override?.edge?.assigned_ip ??
      source?.edge?.assigned_ip ??
      ("edge" in record ? record.edge?.assigned_ip : record.edge_ip);
    const nodeId =
      override?.edge?.assigned_node_id ??
      source?.edge?.assigned_node_id ??
      ("edge" in record ? record.edge?.assigned_node_id : record.edge_node_id);
    const labels =
      override?.edge?.labels ??
      source?.edge?.labels ??
      ("edge" in record
        ? (record.edge?.labels ?? [])
        : (record.edge_labels ?? []));
    const originIp =
      override?.origin_ip ?? source?.origin_ip ?? record.origin_ip;
    const proxied = override?.proxied ?? source?.proxied ?? record.proxied;
    const ttl =
      override?.ttl ??
      source?.ttl ??
      ("ttl" in record ? ((record as any).ttl ?? 60) : 60);
    const nodeName = nodeId
      ? edgeEndpoints.find((edge) => edge.node_id === nodeId)?.node_name
      : assignedIp
        ? edgeEndpoints.find((edge) => edge.ip === assignedIp)?.node_name
        : undefined;
    return {
      domain: record.domain,
      origin_ip: originIp,
      proxied,
      ttl,
      labels,
      assigned_ip: assignedIp,
      node_id: nodeId,
      node_name: nodeName,
    };
  };

  const openEdgeModal = (record: Domain | DomainOverview) => {
    if (!isAdmin) {
      return;
    }
    setEdgeModalData(buildEdgeModalData(record));
  };

  const renderEdgeCell = (record: Domain | DomainOverview) => {
    if (!isAdmin) {
      return null;
    }
    const info = buildEdgeModalData(record);
    const displayLabel = info.proxied
      ? info.assigned_ip || "Pending assignment"
      : "Proxy disabled";
    const ipClass = info.proxied && info.assigned_ip ? "" : "edge-ip-muted";
    const nodeSuffix =
      info.proxied && info.node_name ? ` (${info.node_name})` : "";
    return (
      <div className="edge-cell">
        <div className="edge-assignment">
          <span
            className={`edge-ip mono ${ipClass}`}
            title={
              info.node_id
                ? `Node ${info.node_name || info.node_id} (${info.node_id})`
                : undefined
            }
          >
            {displayLabel}
            {nodeSuffix}
          </span>
        </div>
        {info.labels.length > 0 && (
          <div className="edge-labels">
            {info.labels.map((label) => (
              <Badge
                key={`${record.domain}-edge-label-${label}`}
                variant="secondary"
                size="sm"
              >
                {label}
              </Badge>
            ))}
          </div>
        )}
        <div className="edge-actions">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => openEdgeModal(record)}
          >
            Configure
          </Button>
        </div>
      </div>
    );
  };

  const handleToggleProxy = async (domain: Domain | DomainOverview) => {
    try {
      const domainName = "domain" in domain ? domain.domain : domain.domain;
      const newProxied = !domain.proxied;

      // If disabling proxy, also disable TLS
      const tlsPayload = !newProxied
        ? { mode: "off" as const, use_recommended: false }
        : undefined;

      const updated = await domainsApi.update(domainName, {
        origin_ip: domain.origin_ip,
        proxied: newProxied,
        ttl: "ttl" in domain ? domain.ttl : 60,
        tls: tlsPayload,
      });

      if (viewMode === "my") {
        setDomains(domains.map((d) => (d.domain === domainName ? updated : d)));
      }
      loadData(false);
      toast.success(
        `Proxy ${newProxied ? "enabled" : "disabled"} for ${domainName}`,
      );
    } catch (error) {
      toast.error("Failed to update proxy setting");
    }
  };

  const handleChangeTLS = async (
    domain: Domain | DomainOverview,
    mode: string,
  ) => {
    try {
      const domainName = "domain" in domain ? domain.domain : domain.domain;

      if (!domain.proxied && mode !== "off") {
        toast.error("Enable proxy first to use TLS");
        return;
      }

      let newMode: any;
      let useRecommended = false;

      if (mode === "auto") {
        newMode = "flexible";
        useRecommended = true;
      } else {
        newMode = mode;
      }

      const updated = await domainsApi.update(domainName, {
        origin_ip: domain.origin_ip,
        proxied: domain.proxied,
        ttl: "ttl" in domain ? domain.ttl : 60,
        tls: {
          mode: newMode,
          use_recommended: useRecommended,
        },
      });

      if (viewMode === "my") {
        setDomains(domains.map((d) => (d.domain === domainName ? updated : d)));
      }
      loadData(false);
      toast.success(`TLS mode updated for ${domainName}`);
    } catch (error: any) {
      toast.error(
        error.response?.data?.error || "Failed to update TLS setting",
      );
    }
  };

  const handleEditIP = (domain: Domain | DomainOverview) => {
    const domainName = "domain" in domain ? domain.domain : domain.domain;
    setEditingDomain(domainName);
    setEditingIP(domain.origin_ip);
    setTimeout(() => editInputRef.current?.select(), 0);
  };

  const handleSaveIP = async (domain: Domain | DomainOverview) => {
    const domainName = "domain" in domain ? domain.domain : domain.domain;

    if (!editingIP || editingIP === domain.origin_ip) {
      setEditingDomain(null);
      return;
    }

    try {
      const updated = await domainsApi.update(domainName, {
        origin_ip: editingIP,
        proxied: domain.proxied,
        ttl: "ttl" in domain ? domain.ttl : 60,
      });

      if (viewMode === "my") {
        setDomains(domains.map((d) => (d.domain === domainName ? updated : d)));
      }
      loadData(false);
      toast.success(`Updated IP for ${domainName}`);
    } catch (error) {
      toast.error("Failed to update IP address");
    } finally {
      setEditingDomain(null);
    }
  };

  const handleDeleteSelected = async () => {
    if (selectedDomains.size === 0) return;

    if (!confirm(`Delete ${selectedDomains.size} domain(s)?`)) return;

    try {
      await Promise.all(
        Array.from(selectedDomains).map((d) => domainsApi.delete(d)),
      );
      setDomains(domains.filter((d) => !selectedDomains.has(d.domain)));
      setSelectedDomains(new Set());
      loadData(false);
      toast.success(`Deleted ${selectedDomains.size} domain(s)`);
    } catch (error) {
      toast.error("Failed to delete domains");
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
        payload.tls = { mode: "off", use_recommended: false };
      }

      const response = await domainsApi.bulkUpdate(payload);
      toast.success(`Updated ${response.success} domain(s)`);

      if (response.failed > 0) {
        toast.error(`Failed to update ${response.failed} domain(s)`);
      }

      loadData(false);
      setSelectedDomains(new Set());
    } catch (error) {
      toast.error("Failed to update domains");
    }
  };

  const handleBulkTLSUpdate = async (mode: string) => {
    if (selectedDomains.size === 0) return;

    try {
      const response = await domainsApi.bulkUpdate({
        domains: Array.from(selectedDomains),
        tls: {
          mode: mode === "auto" ? "flexible" : (mode as any),
          use_recommended: mode === "auto",
        },
      });
      toast.success(`Updated TLS for ${response.success} domain(s)`);

      if (response.failed > 0) {
        toast.error(`Failed to update ${response.failed} domain(s)`);
      }

      loadData(false);
      setSelectedDomains(new Set());
    } catch (error) {
      toast.error("Failed to update TLS settings");
    }
  };

  const handleBulkIPUpdate = async () => {
    if (selectedDomains.size === 0) return;
    const ip = bulkIP.trim();
    if (!ip) {
      toast.error("Enter a new origin IP address");
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
      setBulkIP("");
      setSelectedDomains(new Set());
      loadData(false);
    } catch (error: any) {
      toast.error(error.response?.data?.error || "Failed to update origin IP");
    }
  };

  const handleBulkOwnerUpdate = async () => {
    if (selectedDomains.size === 0) return;
    const owner = bulkOwner.trim();
    if (!owner) {
      toast.error("Enter a new owner (email or ID)");
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
      setBulkOwner("");
      setSelectedDomains(new Set());
      loadData(false);
    } catch (error: any) {
      toast.error(
        error.response?.data?.error || "Failed to update domain owner",
      );
    }
  };

  const handleSaveEdgeLabels = async (
    data: EdgeModalData,
    labels: string[],
  ) => {
    if (!isAdmin) {
      return;
    }
    try {
      const updated = await domainsApi.update(data.domain, {
        origin_ip: data.origin_ip,
        proxied: data.proxied,
        ttl: data.ttl,
        edge: { labels },
      });
      setEdgeModalData(buildEdgeModalData(updated, updated));
      await loadData(false);
      toast.success("Edge labels updated");
    } catch (error: any) {
      toast.error(
        error.response?.data?.error || "Failed to update edge labels",
      );
    }
  };

  const handleReassignEdge = async (data: EdgeModalData) => {
    if (!isAdmin) {
      return;
    }
    try {
      const updated = await domainsApi.reassignEdge(data.domain);
      setEdgeModalData(buildEdgeModalData(updated, updated));
      await loadData(false);
      toast.success("Edge assignment updated");
    } catch (error: any) {
      toast.error(error.response?.data?.error || "Failed to reassign edge");
    }
  };

  const getTLSDisplay = (domain: Domain | DomainOverview) => {
    const isFullDomain = "tls" in domain;

    if (!isFullDomain) {
      // DomainOverview - limited TLS info
      const statusKey = domain.tls_status || "none";
      const currentValue = domain.tls_use_recommended
        ? "auto"
        : domain.tls_mode || "off";
      const retryHint = computeRetryHint(domain.tls_retry_after);

      // Admin can edit all domains
      const canEdit =
        isAdmin || domains.some((d) => d.domain === domain.domain);

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
              Auto →{" "}
              {domain.tls_recommended_mode
                ? modeLabel(domain.tls_recommended_mode)
                : "detecting…"}
            </span>
          )}
          {renderStatusIndicator(statusKey, domain.tls_last_error, retryHint)}
          {/* Show error icon for errored status */}
          {domain.tls_status === "errored" && domain.tls_last_error && (
            <div className="tls-error-tooltip" title={domain.tls_last_error}>
              ⚠️
            </div>
          )}
        </div>
      );
    }

    // Full Domain with complete TLS data
    const statusKey = domain.tls.status || "none";
    const currentValue = domain.tls.use_recommended ? "auto" : domain.tls.mode;
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
            Auto →{" "}
            {domain.tls.recommended_mode
              ? modeLabel(domain.tls.recommended_mode)
              : "detecting…"}
          </span>
        )}
        {renderStatusIndicator(statusKey, domain.tls.last_error, retryHint)}
        {/* Show error icon for errored status */}
        {domain.tls.status === "errored" && domain.tls.last_error && (
          <div className="tls-error-tooltip" title={domain.tls.last_error}>
            ⚠️
          </div>
        )}
      </div>
    );
  };

  const getFilteredData = () => {
    const query = searchQuery.toLowerCase();
    const matchesLabel = (record: Domain | DomainOverview) => {
      if (!isAdmin || labelFilter === "all") {
        return true;
      }
      const labels = getDomainLabels(record);
      if (labelFilter === "unlabeled") {
        return labels.length === 0;
      }
      return labels.includes(labelFilter);
    };

    if (viewMode === "my") {
      return domains.filter(
        (d) =>
          (d.domain.toLowerCase().includes(query) ||
            d.origin_ip.includes(searchQuery)) &&
          matchesLabel(d),
      );
    }

    if (viewMode === "orphaned") {
      return allDomains.filter(
        (d) =>
          !d.owner_exists &&
          (d.domain.toLowerCase().includes(query) ||
            d.origin_ip.includes(searchQuery) ||
            d.owner_email?.toLowerCase().includes(query)) &&
          matchesLabel(d),
      );
    }

    // All domains mode - search by domain, IP, or email
    return allDomains.filter(
      (d) =>
        (d.domain.toLowerCase().includes(query) ||
          d.owner_email?.toLowerCase().includes(query) ||
          d.origin_ip.includes(searchQuery)) &&
        matchesLabel(d),
    );
  };

  const filteredData = getFilteredData();
  const orphanedCount = allDomains.filter((d) => !d.owner_exists).length;
  const selectionEnabled =
    viewMode === "my" ||
    (isAdmin && (viewMode === "all" || viewMode === "orphaned"));

  // Build unified columns array
  const columns: any[] = [];

  // Domain column - always present
  columns.push({
    key: "domain",
    header: "Domain",
    accessor: (d: any) => (
      <div className="domain-cell">
        <span className="domain-name mono">{d.domain}</span>
        {d.owner_exists === false && (
          <Badge variant="warning" size="sm">
            Orphaned
          </Badge>
        )}
      </div>
    ),
  });

  // Owner column - only for admin in all/orphaned mode
  if (isAdmin && viewMode !== "my") {
    columns.push({
      key: "owner",
      header: "Owner",
      accessor: (d: any) => (
        <div className="owner-cell">
          {d.owner_email ? (
            <span className="owner-email">{d.owner_email}</span>
          ) : (
            <span className="owner-missing">No owner</span>
          )}
        </div>
      ),
      width: "180px",
    });
  }

  // Origin IP column - always present
  columns.push({
    key: "origin_ip",
    header: "Origin IP",
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
              if (e.key === "Enter") handleSaveIP(d);
              if (e.key === "Escape") setEditingDomain(null);
            }}
          />
        ) : (
          <span className="ip-display mono" onClick={() => handleEditIP(d)}>
            {d.origin_ip}
            <svg
              className="edit-icon"
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
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
    key: "proxied",
    header: "Proxy",
    accessor: (d: any) => (
      <Switch
        checked={d.proxied}
        onChange={() => handleToggleProxy(d)}
        size="sm"
      />
    ),
    width: "100px",
    align: "center" as const,
  });

  if (isAdmin) {
    columns.push({
      key: "edge-assignment",
      header: "Edge",
      accessor: (d: any) => renderEdgeCell(d),
      width: "220px",
    });
  }

  // TLS column - always present
  columns.push({
    key: "tls",
    header: "TLS",
    accessor: (d: any) => getTLSDisplay(d),
    width: "200px",
  });

  // TTL column - always present
  columns.push({
    key: "ttl",
    header: "TTL",
    accessor: (d: any) => <span className="mono">{d.ttl || 300}s</span>,
    width: "80px",
    align: "right" as const,
  });

  // Updated column - always present
  columns.push({
    key: "updated",
    header: "Updated",
    accessor: (d: any) => (
      <span className="text-secondary">
        {format(new Date(d.updated_at), "MMM d, HH:mm")}
      </span>
    ),
    width: "140px",
  });

  return (
    <div className="domain-management">
      <PageHeader
        title={isAdmin ? "Domain Management" : "Your Domains"}
        subtitle={
          viewMode === "my"
            ? `${domains.length} domains registered`
            : viewMode === "orphaned"
              ? `${orphanedCount} orphaned domains`
              : `${allDomains.length} total domains`
        }
        searchPlaceholder={
          isAdmin && viewMode !== "my"
            ? "Search domains, IPs or users..."
            : "Search domains or IPs..."
        }
        searchValue={searchQuery}
        onSearchChange={setSearchQuery}
      >
        {selectedDomains.size > 0 && selectionEnabled && (
          <>
            <div className="batch-actions">
              <div className="batch-toggle-group">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => handleBulkProxyToggle(true)}
                >
                  Enable Proxy
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => handleBulkProxyToggle(false)}
                >
                  Disable Proxy
                </Button>
                <select
                  className="batch-tls-select"
                  onChange={(e) =>
                    e.target.value && handleBulkTLSUpdate(e.target.value)
                  }
                  defaultValue=""
                >
                  <option value="" disabled>
                    TLS Mode...
                  </option>
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
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={handleBulkIPUpdate}
                  disabled={!bulkIP.trim()}
                >
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
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={handleBulkOwnerUpdate}
                    disabled={!bulkOwner.trim()}
                  >
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
        {isAdmin && availableLabels.length > 0 && (
          <div className="label-filter">
            <select
              value={labelFilter}
              onChange={(e) => setLabelFilter(e.target.value)}
            >
              <option value="all">All labels</option>
              <option value="unlabeled">No label</option>
              {availableLabels.map((label) => (
                <option key={label} value={label}>
                  {label}
                </option>
              ))}
            </select>
          </div>
        )}
        <Button variant="primary" onClick={() => setShowAddDomain(true)}>
          Add Domain
        </Button>
      </PageHeader>

      {isAdmin && (
        <div className="filter-tabs">
          <button
            className={`filter-tab ${viewMode === "my" ? "active" : ""}`}
            onClick={() => {
              setViewMode("my");
              setSelectedDomains(new Set());
            }}
          >
            My Domains
            <span className="tab-count">{domains.length}</span>
          </button>
          <button
            className={`filter-tab ${viewMode === "all" ? "active" : ""}`}
            onClick={() => {
              setViewMode("all");
              setSelectedDomains(new Set());
            }}
          >
            All Domains
            <span className="tab-count">{allDomains.length}</span>
          </button>
          <button
            className={`filter-tab ${viewMode === "orphaned" ? "active" : ""}`}
            onClick={() => {
              setViewMode("orphaned");
              setSelectedDomains(new Set());
            }}
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
          onRowSelect={
            selectionEnabled
              ? (id, selected) => {
                  const newSelected = new Set(selectedDomains);
                  if (selected) {
                    newSelected.add(id);
                  } else {
                    newSelected.delete(id);
                  }
                  setSelectedDomains(newSelected);
                }
              : undefined
          }
          onSelectAll={
            selectionEnabled
              ? (selected) => {
                  if (selected) {
                    setSelectedDomains(
                      new Set(filteredData.map((d: any) => d.domain)),
                    );
                  } else {
                    setSelectedDomains(new Set());
                  }
                }
              : undefined
          }
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
          <p className="ns-hint">
            Configure these nameservers at your domain registrar
          </p>
        </Card>
      )}

      {showAddDomain && (
        <AddDomainModal
          onClose={() => setShowAddDomain(false)}
          onAdd={loadData}
          isAdmin={isAdmin}
        />
      )}
      {isAdmin && edgeModalData && (
        <EdgeSettingsModal
          data={edgeModalData}
          onClose={() => setEdgeModalData(null)}
          onSaveLabels={(labels) => handleSaveEdgeLabels(edgeModalData, labels)}
          onReassign={() => handleReassignEdge(edgeModalData)}
        />
      )}
    </div>
  );
}

function AddDomainModal({
  onClose,
  onAdd,
  isAdmin,
}: {
  onClose: () => void;
  onAdd: (showLoader?: boolean) => void;
  isAdmin: boolean;
}) {
  const [formData, setFormData] = useState<CreateDomainPayload>({
    domain: "",
    origin_ip: "",
    proxied: true,
    ttl: 60,
    tls: {
      mode: "flexible",
      use_recommended: true,
    },
  });
  const [bulkMode, setBulkMode] = useState(false);
  const [bulkDomains, setBulkDomains] = useState("");
  const [edgeLabels, setEdgeLabels] = useState("");
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
      const parsedLabels = isAdmin
        ? edgeLabels
            .split(/[\n,]/)
            .map((label) => label.trim())
            .filter(Boolean)
        : [];
      const edgePayload =
        isAdmin && parsedLabels.length > 0
          ? { labels: parsedLabels }
          : undefined;
      if (bulkMode) {
        const domainList = bulkDomains
          .split("\n")
          .map((d) => d.trim())
          .filter(Boolean);
        await domainsApi.bulkCreate({
          domains: domainList,
          origin_ip: formData.origin_ip,
          proxied: formData.proxied,
          ttl: formData.ttl,
          tls: formData.tls,
          edge: edgePayload,
        });
        toast.success(`Added ${domainList.length} domains`);
      } else {
        await domainsApi.create({
          ...formData,
          edge: edgePayload,
        });
        toast.success(`Added ${formData.domain}`);
      }
      onAdd(false);
      onClose();
    } catch (error: any) {
      toast.error(error.response?.data?.error || "Failed to add domain");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="modal-overlay"
      onMouseDown={handleMouseDown}
      onMouseUp={handleMouseUp}
    >
      <div className="modal" ref={modalRef}>
        <div className="modal-header">
          <h2>Add Domain</h2>
          <button className="modal-close" onClick={onClose}>
            ✕
          </button>
        </div>
        <form onSubmit={handleSubmit} className="modal-body">
          <div className="form-tabs">
            <button
              type="button"
              className={`tab ${!bulkMode ? "tab-active" : ""}`}
              onClick={() => setBulkMode(false)}
            >
              Single Domain
            </button>
            <button
              type="button"
              className={`tab ${bulkMode ? "tab-active" : ""}`}
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
              onChange={(e) =>
                setFormData({ ...formData, domain: e.target.value })
              }
              fullWidth
              required
            />
          )}

          <Input
            label="Origin IP"
            placeholder="192.168.1.1"
            value={formData.origin_ip}
            onChange={(e) =>
              setFormData({ ...formData, origin_ip: e.target.value })
            }
            fullWidth
            required
          />

          <div className="form-row">
            <Input
              type="number"
              label="TTL (seconds)"
              value={formData.ttl}
              onChange={(e) =>
                setFormData({
                  ...formData,
                  ttl: parseInt(e.target.value) || 60,
                })
              }
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
                    newFormData.tls = { mode: "off", use_recommended: false };
                  } else if (formData.tls?.mode === "off") {
                    // Re-enable TLS when enabling proxy
                    newFormData.tls = {
                      mode: "flexible",
                      use_recommended: true,
                    };
                  }
                  setFormData(newFormData);
                }}
                label={formData.proxied ? "Enabled" : "Disabled"}
              />
            </div>
          </div>

          {isAdmin && (
            <div className="form-group">
              <label>Edge Labels</label>
              <Input
                placeholder="Comma separated (e.g. edge-eu, premium)"
                value={edgeLabels}
                onChange={(e) => setEdgeLabels(e.target.value)}
                fullWidth
              />
              <p className="form-hint">
                Optional. Labels control which edge nodes serve this domain.
              </p>
            </div>
          )}

          {formData.proxied && (
            <div className="form-group">
              <label>TLS Mode</label>
              <div className="tls-mode-select-wrapper">
                <select
                  className="form-select"
                  value={
                    formData.tls?.use_recommended
                      ? "auto"
                      : formData.tls?.mode || "off"
                  }
                  onChange={(e) => {
                    const value = e.target.value;
                    if (value === "auto") {
                      setFormData({
                        ...formData,
                        tls: { mode: "flexible", use_recommended: true },
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
                <p className="tls-hint">
                  Auto mode will detect the best TLS configuration for your
                  origin
                </p>
              </div>
            </div>
          )}

          <div className="modal-actions">
            <Button variant="ghost" onClick={onClose} disabled={loading}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={loading}>
              Add {bulkMode ? "Domains" : "Domain"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

function EdgeSettingsModal({
  data,
  onClose,
  onSaveLabels,
  onReassign,
}: {
  data: EdgeModalData;
  onClose: () => void;
  onSaveLabels: (labels: string[]) => Promise<void>;
  onReassign: () => Promise<void>;
}) {
  const [labelsInput, setLabelsInput] = useState(data.labels.join(", "));
  const [saving, setSaving] = useState(false);
  const [reassigning, setReassigning] = useState(false);
  const modalRef = useRef<HTMLDivElement>(null);
  const [isMouseDown, setIsMouseDown] = useState(false);

  useEffect(() => {
    setLabelsInput(data.labels.join(", "));
  }, [data]);

  const parseLabels = (value: string) =>
    value
      .split(/[\n,]/)
      .map((label) => label.trim())
      .filter(Boolean);

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
    setSaving(true);
    try {
      await onSaveLabels(parseLabels(labelsInput));
    } finally {
      setSaving(false);
    }
  };

  const handleReassignClick = async () => {
    setReassigning(true);
    try {
      await onReassign();
    } finally {
      setReassigning(false);
    }
  };

  return (
    <div
      className="modal-overlay"
      onMouseDown={handleMouseDown}
      onMouseUp={handleMouseUp}
    >
      <div className="modal" ref={modalRef}>
        <div className="modal-header">
          <h2>Edge Assignment</h2>
          <button className="modal-close" onClick={onClose}>
            ✕
          </button>
        </div>
        <form onSubmit={handleSubmit} className="modal-body">
          <div className="form-group">
            <label>Domain</label>
            <div className="edge-modal-domain mono">{data.domain}</div>
          </div>
          <div className="form-group">
            <label>Assigned Edge IP</label>
            <div className="edge-modal-assignment">
              <span className="mono edge-modal-ip">
                {data.assigned_ip || "Pending assignment"}
                {data.node_name ? ` (${data.node_name})` : ""}
              </span>
              {data.node_id && (
                <span className="edge-modal-node mono">
                  Node ID: {data.node_id}
                </span>
              )}
            </div>
            {!data.proxied && (
              <p className="form-hint">
                Enable proxy to activate edge routing for this domain.
              </p>
            )}
          </div>
          <div className="form-group">
            <label>Labels</label>
            <Input
              placeholder="Comma separated labels"
              value={labelsInput}
              onChange={(e) => setLabelsInput(e.target.value)}
              fullWidth
            />
            <p className="form-hint">
              Labels control which nodes participate in the rotation for this
              domain.
            </p>
          </div>
          <div className="modal-actions edge-modal-actions">
            <Button
              variant="ghost"
              type="button"
              onClick={onClose}
              disabled={saving || reassigning}
            >
              Close
            </Button>
            <Button
              variant="secondary"
              type="button"
              onClick={handleReassignClick}
              loading={reassigning}
              disabled={!data.proxied || reassigning}
            >
              Reassign
            </Button>
            <Button variant="primary" type="submit" loading={saving}>
              Save Labels
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
