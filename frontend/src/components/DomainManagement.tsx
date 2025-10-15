import React, { useState, useEffect, useRef } from "react";
import { domains as domainsApi, infra, admin } from "../api/client";
import {
  Domain,
  CreateDomainPayload,
  NameServerEntry,
  DomainOverview,
  EdgeEndpoint,
  DomainNameserverEntry,
  DomainNameserverSet,
  DomainWhois,
} from "../types";
import Table from "./ui/Table";
import Button from "./ui/Button";
import Input from "./ui/Input";
import Switch from "./ui/Switch";
import Badge from "./ui/Badge";
import Card from "./ui/Card";
import PageHeader from "./PageHeader";
import toast from "react-hot-toast";
import { format, formatDistanceToNow, differenceInCalendarDays } from "date-fns";
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
  const [rebalancingEdges, setRebalancingEdges] = useState(false);
  const [purgingDomain, setPurgingDomain] = useState<string | null>(null);
  const [expandedNameservers, setExpandedNameservers] = useState<string | null>(
    null,
  );
  const [refreshingWhois, setRefreshingWhois] = useState<Set<string>>(
    new Set(),
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

  useEffect(() => {
    setExpandedNameservers(null);
  }, [viewMode, searchQuery, isAdmin]);

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

  const renderNameserverCategory = (
    label: string,
    entries?: DomainNameserverEntry[],
    options?: { showIPs?: boolean; header?: string },
  ): React.ReactNode => {
    if (!entries || entries.length === 0) {
      return null;
    }
    const showIPs = options?.showIPs ?? true;
    const header = options?.header ?? label;
    return (
      <div className="ns-category" key={header}>
        <div className="ns-category-header">{header}</div>
        {entries.map((entry) => (
          <div className="ns-row" key={`${header}-${entry.name}`}>
            <span className="ns-host">{entry.name}</span>
            {showIPs && entry.ipv4 && <span className="ns-ip">{entry.ipv4}</span>}
          </div>
        ))}
      </div>
    );
  };

  const renderNameserverCell = (record: Domain | DomainOverview) => {
    const nsSet = (record as { nameservers?: DomainNameserverSet }).nameservers;
    const domainName = (record as { domain: string }).domain;
    if (
      !nsSet ||
      (!nsSet.default?.length &&
        !nsSet.anycast?.length &&
        !nsSet.vanity?.length)
    ) {
      return <span className="text-secondary">—</span>;
    }
    const hasAnycast = Array.isArray(nsSet.anycast) && nsSet.anycast.length > 0;
    const primary =
      hasAnycast && nsSet.anycast
        ? nsSet.anycast
        : nsSet.vanity && nsSet.vanity.length > 0
          ? nsSet.vanity
          : [];
    if (!primary.length) {
      return <span className="text-secondary">—</span>;
    }
    const visible = primary.slice(0, 4);
    const remaining = Math.max(primary.length - visible.length, 0);
    const anycastSection = renderNameserverCategory(
      "Anycast",
      nsSet.anycast,
      {
        showIPs: false,
      },
    );
    const vanitySection = renderNameserverCategory(
      "Domain-specific (NameServers + Glue)",
      nsSet.vanity,
      { showIPs: true, header: "Domain-specific (NameServers + Glue)" },
    );
    const sections = [anycastSection, vanitySection].filter(
      (section): section is React.ReactNode => Boolean(section),
    );
    const hasDetails = sections.length > 0;
    const isOpen = expandedNameservers === domainName;
    const toggle = () => {
      if (!hasDetails) {
        return;
      }
      setExpandedNameservers((prev) =>
        prev === domainName ? null : domainName,
      );
    };
    return (
      <div className="nameserver-cell">
        <div
          className="ns-primary"
          role={hasDetails ? "button" : undefined}
          tabIndex={hasDetails ? 0 : -1}
          aria-expanded={hasDetails ? isOpen : undefined}
          onClick={toggle}
          onKeyDown={(event) => {
            if (!hasDetails) {
              return;
            }
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              toggle();
            }
          }}
        >
          {visible.map((entry) => (
            <span
              key={`${domainName}-${entry.name}`}
              className="ns-chip mono"
              title={entry.name}
            >
              {entry.name}
            </span>
          ))}
          {remaining > 0 && (
            <span className="ns-more" title={`+${remaining} more`}>+{remaining} more</span>
          )}
        </div>
        {isOpen && hasDetails && (
          <div className="ns-popover">{sections}</div>
        )}
      </div>
    );
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

  const markWhoisRefreshing = (domainName: string, refreshing: boolean) => {
    setRefreshingWhois((current) => {
      const next = new Set(current);
      if (refreshing) {
        next.add(domainName);
      } else {
        next.delete(domainName);
      }
      return next;
    });
  };

const resolveWhois = (
  record: Domain | DomainOverview,
): DomainWhois | undefined => {
  const full = findFullDomain(record.domain);
  if (full?.whois) {
    return full.whois;
  }
  if ("whois" in record) {
    return record.whois;
  }
  return undefined;
};

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
    const ttl = override?.ttl ?? source?.ttl ?? record.ttl;
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

  const handleManualWhois = async (
    record: Domain | DomainOverview,
    whois?: DomainWhois,
    options?: { skipReload?: boolean },
  ) => {
    const domainName = record.domain;
    let fallbackExpiry = "";
    if (whois?.expires_at) {
      const parsed = new Date(whois.expires_at);
      fallbackExpiry = Number.isNaN(parsed.getTime())
        ? whois.expires_at
        : format(parsed, "yyyy-MM-dd");
    }
    const previousValue = whois?.raw_expires
      ? whois.raw_expires
      : fallbackExpiry;
    const parts: string[] = [];
    if (whois?.last_error) {
      parts.push(`Last error: ${whois.last_error}`);
    }
    if (previousValue) {
      parts.push(`Previous value: ${previousValue}`);
    }
    parts.push("Enter new expiration date (YYYY-MM-DD or RFC3339)");
    const promptText = parts.join("\n");
    const input = window.prompt(
      `${domainName} renewal override\n${promptText}`,
      previousValue,
    );
    if (!input) {
      return;
    }
    const normalized = input.trim();
    if (!normalized) {
      toast.error("Expiration date is required");
      return;
    }
    try {
      const updated = await domainsApi.overrideWhois(domainName, {
        expires_at: normalized,
        raw_input: normalized,
      });
      toast.success(`Renewal date saved for ${domainName}`);
      setDomains((current) =>
        current.some((d) => d.domain === domainName)
          ? current.map((d) => (d.domain === domainName ? updated : d))
          : current,
      );
      setAllDomains((current) =>
        current.map((entry) =>
          entry.domain === domainName
            ? {
                ...entry,
                whois: updated.whois,
                updated_at: updated.updated_at,
                proxied: updated.proxied,
                origin_ip: updated.origin_ip ?? entry.origin_ip,
                ttl: updated.ttl,
              }
            : entry,
        ),
      );
      if (!options?.skipReload) {
        loadData(false);
      }
    } catch (error: any) {
      const message =
        error?.response?.data?.error ||
        "Failed to save manual WHOIS information";
      toast.error(message);
    } finally {
      // no-op
    }
  };

  const handleRefreshWhois = async (record: Domain | DomainOverview) => {
    const domainName = record.domain;
    markWhoisRefreshing(domainName, true);
    try {
      const updated = await domainsApi.refreshWhois(domainName);
      setDomains((current) =>
        current.some((d) => d.domain === domainName)
          ? current.map((d) => (d.domain === domainName ? updated : d))
          : current,
      );
      setAllDomains((current) =>
        current.map((entry) =>
          entry.domain === domainName
            ? {
                ...entry,
                whois: updated.whois,
                updated_at: updated.updated_at,
                proxied: updated.proxied,
                origin_ip: updated.origin_ip ?? entry.origin_ip,
                ttl: updated.ttl,
              }
            : entry,
        ),
      );

      const whois = updated.whois;
      if (whois?.expires_at && !whois.last_error) {
        const expiry = new Date(whois.expires_at);
        if (!Number.isNaN(expiry.getTime())) {
          const diff = differenceInCalendarDays(expiry, new Date());
          const suffix = Math.abs(diff) === 1 ? "day" : "days";
          toast.success(
            diff >= 0
              ? `WHOIS updated: ${diff} ${suffix} remaining`
              : `WHOIS updated: expired ${Math.abs(diff)} ${suffix} ago`,
          );
        } else {
          toast.success("WHOIS refreshed");
        }
      } else {
        const message =
          whois?.last_error ||
          "WHOIS data unavailable. Please update the renewal date manually.";
        toast.error(message);
        markWhoisRefreshing(domainName, false);
        await handleManualWhois(updated, whois, { skipReload: true });
      }
      loadData(false);
    } catch (error: any) {
      const message =
        error?.response?.data?.error || "Failed to refresh WHOIS details";
      toast.error(message);
    } finally {
      markWhoisRefreshing(domainName, false);
    }
  };

  const renderWhoisCell = (record: Domain | DomainOverview) => {
    const whois = resolveWhois(record);
    const isRefreshing = refreshingWhois.has(record.domain);

    let label = "—";
    let tone: "critical" | "warning" | "ok" | "neutral" | "unknown" = "neutral";
    let tooltip: string | undefined;

    if (whois?.expires_at) {
      const expiry = new Date(whois.expires_at);
      if (
        !Number.isNaN(expiry.getTime()) &&
        expiry.getUTCFullYear() > 1900
      ) {
        const days = differenceInCalendarDays(expiry, new Date());
        label = days.toString();
        if (days < 0 || days < 30) {
          tone = "critical";
        } else if (days < 90) {
          tone = "warning";
        } else {
          tone = "ok";
        }
        const tooltipParts = [`Expires on ${format(expiry, "yyyy-MM-dd")}`];
        if (whois.raw_expires && whois.raw_expires !== whois.expires_at) {
          tooltipParts.push(`Raw: ${whois.raw_expires}`);
        }
        if (whois.checked_at) {
          const checked = new Date(whois.checked_at);
          if (!Number.isNaN(checked.getTime())) {
            tooltipParts.push(
              `Checked ${formatDistanceToNow(checked, { addSuffix: true })}`,
            );
          }
        }
        tooltip = tooltipParts.join("\n");
      }
    } else if (whois?.last_error) {
      const message = whois.last_error.toLowerCase();
      if (message.includes("expiration not found")) {
        label = "🤷";
        tone = "unknown";
      }
      tooltip = whois.last_error;
    } else if (!whois) {
      label = "—";
    }

    const displayValue = isRefreshing ? "…" : label;

    return (
      <div className="whois-cell">
        <button
          type="button"
          className={`whois-trigger whois-trigger--${tone}`}
          onClick={(event) => {
            event.stopPropagation();
            handleRefreshWhois(record);
          }}
          title={tooltip}
          disabled={isRefreshing}
        >
          {displayValue}
        </button>
        <button
          type="button"
          className="whois-manual-link"
          onClick={(event) => {
            event.stopPropagation();
            handleManualWhois(record, whois);
          }}
          title="Set expiration manually"
        >
          Set
        </button>
      </div>
    );
  };

  const handleToggleProxy = async (domain: Domain | DomainOverview) => {
    try {
      const domainName = "domain" in domain ? domain.domain : domain.domain;
      const newProxied = !domain.proxied;
      const rawOrigin = (domain as any).origin_ip ?? "";
      const currentOrigin =
        typeof rawOrigin === "string" ? rawOrigin.trim() : "";

      // If disabling proxy, also disable TLS
      const tlsPayload = !newProxied
        ? { mode: "off" as const, use_recommended: false }
        : undefined;

      const updated = await domainsApi.update(domainName, {
        origin_ip: currentOrigin,
        proxied: newProxied,
        ttl: domain.ttl,
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

      const originRaw = (domain as any).origin_ip ?? "";
      const originValue =
        typeof originRaw === "string" ? originRaw.trim() : "";

      let newMode: any;
      let useRecommended = false;

      if (mode === "auto") {
        newMode = "flexible";
        useRecommended = true;
      } else {
        newMode = mode;
      }

      const updated = await domainsApi.update(domainName, {
        origin_ip: originValue,
        proxied: domain.proxied,
        ttl: domain.ttl,
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

  const handlePurgeCache = async (domainName: string) => {
    try {
      setPurgingDomain(domainName);
      await domainsApi.purgeCache(domainName);
      await loadData(false);
      toast.success(`Purged cache for ${domainName}`);
    } catch (error: any) {
      toast.error(
        error.response?.data?.error || `Failed to purge cache for ${domainName}`,
      );
    } finally {
      setPurgingDomain(null);
    }
  };

  const renderDomainActions = (record: Domain | DomainOverview) => {
    const domainName = "domain" in record ? record.domain : record.domain;
    const isPurging = purgingDomain === domainName;
    return (
      <div className="domain-actions">
        <Button
          variant="ghost"
          size="sm"
          loading={isPurging}
          onClick={() => handlePurgeCache(domainName)}
        >
          Purge Cache
        </Button>
      </div>
    );
  };

  const handleEditIP = (domain: Domain | DomainOverview) => {
    const domainName = "domain" in domain ? domain.domain : domain.domain;
    setEditingDomain(domainName);
    const current = (domain as any).origin_ip ?? "";
    setEditingIP(typeof current === "string" ? current : "");
    setTimeout(() => editInputRef.current?.select(), 0);
  };

  const handleSaveIP = async (domain: Domain | DomainOverview) => {
    const domainName = "domain" in domain ? domain.domain : domain.domain;

    const normalized = editingIP?.trim() ?? "";
    const current = ((domain as any).origin_ip ?? "")
      .toString()
      .trim();
    if (normalized === current) {
      setEditingDomain(null);
      return;
    }
    try {
      const updated = await domainsApi.update(domainName, {
        origin_ip: normalized,
        proxied: domain.proxied,
        ttl: domain.ttl,
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

  const handleReassignAllEdges = async () => {
    if (!isAdmin || rebalancingEdges) {
      return;
    }
    const confirmed = window.confirm(
      "Rebalance edge assignments for all proxied domains? This will redistribute domains across the current edge pool.",
    );
    if (!confirmed) {
      return;
    }
    setRebalancingEdges(true);
    try {
      const result = await domainsApi.reassignAllEdges();
      if (result.reassigned > 0) {
        toast.success(
          `Reassigned ${result.reassigned} domain${result.reassigned === 1 ? "" : "s"} to new edges`,
        );
      }
      if (result.unchanged > 0) {
        toast.success(
          `${result.unchanged} domain${result.unchanged === 1 ? "" : "s"} already optimal`,
        );
      }
      if (result.skipped > 0) {
        toast(
          `${result.skipped} domain${result.skipped === 1 ? "" : "s"} not proxied and skipped`,
        );
      }
      if (result.failed > 0) {
        toast.error(
          `Failed to rebalance ${result.failed} domain${result.failed === 1 ? "" : "s"}`,
        );
      }
      await loadData(false);
    } catch (error: any) {
      toast.error(
        error.response?.data?.error || "Failed to rebalance edge assignments",
      );
    } finally {
      setRebalancingEdges(false);
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

  columns.push({
    key: "nameservers",
    header: "Nameservers",
    accessor: (d: any) => renderNameserverCell(d),
    width: "260px",
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
    accessor: (d: any) => {
      const originRaw = (d as any).origin_ip ?? "";
      const originValue =
        typeof originRaw === "string" ? originRaw : String(originRaw ?? "");
      const trimmed = originValue.trim();
      const isPlaceholder = trimmed === "";
      const displayValue = isPlaceholder ? "aki.cloud placeholder" : trimmed;

      if (editingDomain === d.domain) {
        return (
          <div className="domain-ip">
            <input
              ref={editInputRef}
              className="ip-edit-input"
              value={editingIP ?? ""}
              onChange={(e) => setEditingIP(e.target.value)}
              onBlur={() => handleSaveIP(d)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleSaveIP(d);
                if (e.key === "Escape") setEditingDomain(null);
              }}
            />
          </div>
        );
      }

      return (
        <div className="domain-ip">
          <span
            className={`ip-display ${isPlaceholder ? "ip-placeholder" : "mono"}`}
            onClick={() => handleEditIP(d)}
            title={displayValue}
          >
            {displayValue}
            {isPlaceholder && (
              <Badge
                variant="secondary"
                size="sm"
                className="placeholder-badge"
              >
                placeholder
              </Badge>
            )}
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
        </div>
      );
    },
  });

  columns.push({
    key: "whois",
    header: "Renewal",
    accessor: (d: any) => renderWhoisCell(d),
    width: "200px",
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
    accessor: (d: any) => <span className="mono">{d.ttl}s</span>,
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

  columns.push({
    key: "actions",
    header: "Actions",
    accessor: (d: any) => renderDomainActions(d),
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
        {isAdmin && (
          <Button
            variant="secondary"
            onClick={handleReassignAllEdges}
            loading={rebalancingEdges}
          >
            Rebalance Edges
          </Button>
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
          availableEdgeLabels={availableLabels}
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
  availableEdgeLabels,
}: {
  onClose: () => void;
  onAdd: (showLoader?: boolean) => void;
  isAdmin: boolean;
  availableEdgeLabels: string[];
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
  const [selectedEdgeLabels, setSelectedEdgeLabels] = useState<string[]>([]);
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
      const edgePayload =
        isAdmin && selectedEdgeLabels.length > 0
          ? { labels: selectedEdgeLabels }
          : undefined;
      const normalizedOrigin = formData.origin_ip?.trim() ?? "";
      const originValue = normalizedOrigin === "" ? "" : normalizedOrigin;
      const ownerValue = formData.owner?.trim();
      if (bulkMode) {
        const domainList = bulkDomains
          .split("\n")
          .map((d) => d.trim())
          .filter(Boolean);
        await domainsApi.bulkCreate({
          domains: domainList,
          origin_ip: originValue,
          proxied: formData.proxied,
          ttl: formData.ttl,
          tls: formData.tls,
          owner: ownerValue,
          edge: edgePayload,
        });
        toast.success(`Added ${domainList.length} domains`);
      } else {
        const payload: CreateDomainPayload = {
          domain: formData.domain.trim(),
          proxied: formData.proxied,
          ttl: formData.ttl,
          tls: formData.tls,
          edge: edgePayload,
          owner: ownerValue || undefined,
          origin_ip: originValue,
        };
        await domainsApi.create(payload);
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
        />
        <p className="form-hint">
          Leave blank to serve the aki.cloud placeholder page (requires the
          Placeholder extension).
        </p>

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

          {isAdmin && availableEdgeLabels.length > 0 && (
            <div className="form-group">
              <label>Edge Node Labels</label>
              <div className="edge-labels-selector">
                {availableEdgeLabels.map((label) => (
                  <label key={label} className="edge-label-checkbox">
                    <input
                      type="checkbox"
                      checked={selectedEdgeLabels.includes(label)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedEdgeLabels([...selectedEdgeLabels, label]);
                        } else {
                          setSelectedEdgeLabels(
                            selectedEdgeLabels.filter((l) => l !== label)
                          );
                        }
                      }}
                    />
                    <span className="label-text">{label}</span>
                  </label>
                ))}
              </div>
              <p className="form-hint">
                Select labels to control which edge nodes serve this domain.
                If no labels selected, any edge node can serve it.
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
