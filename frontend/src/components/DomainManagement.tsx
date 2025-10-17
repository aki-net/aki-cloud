import React, {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
} from "react";
import { domains as domainsApi, infra, admin, waf as wafApi } from "../api/client";
import {
  Domain,
  CreateDomainPayload,
  NameServerEntry,
  DomainOverview,
  EdgeEndpoint,
  DomainNameserverEntry,
  DomainNameserverSet,
  DomainWhois,
  SearchBotDomainStats,
  SearchBotBotStats,
  WAFDefinition,
  DomainRedirectRule,
  DomainRole,
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

const SEARCHBOT_PERIODS: Array<{
  key: "today" | "month" | "year";
  short: string;
  label: string;
}> = [
  { key: "today", short: "T", label: "Today" },
  { key: "month", short: "M", label: "This month" },
  { key: "year", short: "Y", label: "This year" },
];

const SEARCHBOT_ALL_BOTS = [
  { key: "googlebot", label: "Googlebot", icon: "G" },
  { key: "bingbot", label: "Bingbot", icon: "B" },
  { key: "yandexbot", label: "YandexBot", icon: "Y" },
  { key: "baiduspider", label: "Baidu Spider", icon: "Bd" },
];

const SEARCHBOT_PRIMARY_KEYS = ["googlebot"];

const PASSIVE_SEARCHBOT_REFRESH_MS = 60 * 60 * 1000;

const GOOGLEBOT_WAF_PRESET = "allow_googlebot_only";

interface Props {
  isAdmin?: boolean;
}

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

type DomainLike = Domain | DomainOverview;

interface DomainRowMeta {
  position: 'parent' | 'alias' | 'redirect' | 'standalone';
  parentDomain?: string;
  familyId?: string;
  familyIndex?: number;
  familyPosition?: 'first' | 'middle' | 'last' | 'single';
  aliasChildren: DomainWithMeta[];
  redirectChildren: DomainWithMeta[];
  domainRule: DomainRedirectRule | null;
  pathRules: DomainRedirectRule[];
  redirectTarget?: string;
  redirectExternal?: boolean;
}

type DomainWithMeta = DomainLike & { __meta: DomainRowMeta };

interface RoleModalState {
  domain: DomainWithMeta;
  mode: 'alias' | 'redirect' | 'primary';
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
  const [searchBotAvailable, setSearchBotAvailable] = useState<boolean | null>(
    null,
  );
  const [searchBotStats, setSearchBotStats] = useState<
    Record<string, SearchBotDomainStats>
  >({});
  const [searchBotRefreshing, setSearchBotRefreshing] = useState<
    Record<string, boolean>
  >({});
  const [searchBotPrimed, setSearchBotPrimed] = useState(false);
  const [searchBotExporting, setSearchBotExporting] = useState<string | null>(
    null,
  );
  const [wafDefinitions, setWafDefinitions] = useState<WAFDefinition[]>([]);
  const [wafUpdatingDomains, setWafUpdatingDomains] = useState<Set<string>>(new Set());
  const [roleModalState, setRoleModalState] = useState<RoleModalState | null>(null);
  const [redirectRulesModalDomain, setRedirectRulesModalDomain] = useState<DomainWithMeta | null>(null);
  const searchBotLastPassiveRef = useRef<number>(0);
  const [searchBotMenuDomain, setSearchBotMenuDomain] = useState<string | null>(
    null,
  );
  const searchBotMenuRef = useRef<HTMLDivElement | null>(null);
  const editInputRef = useRef<HTMLInputElement>(null);
  const loadDataRef = useRef<() => Promise<void>>();
  const [refreshInterval, setRefreshInterval] = useState<number | null>(null);

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
    let cancelled = false;

    const fetchDefinitions = async () => {
      try {
        const defs = await wafApi.definitions();
        if (!cancelled) {
          setWafDefinitions(defs);
        }
      } catch {
        if (!cancelled) {
          setWafDefinitions([]);
        }
      }
    };

    fetchDefinitions();

    return () => {
      cancelled = true;
    };
  }, []);

  const googlebotPresetDefinition = useMemo(
    () =>
      wafDefinitions.find(
        (definition) => definition.key === GOOGLEBOT_WAF_PRESET,
      ),
    [wafDefinitions],
  );

  useEffect(() => {
    if (!searchBotMenuDomain) {
      return;
    }
    const handleClick = (event: MouseEvent) => {
      const target = event.target as Node | null;
      if (
        searchBotMenuRef.current &&
        target &&
        !searchBotMenuRef.current.contains(target)
      ) {
        setSearchBotMenuDomain(null);
      }
    };
    document.addEventListener("mousedown", handleClick);
    return () => {
      document.removeEventListener("mousedown", handleClick);
    };
  }, [searchBotMenuDomain]);

  useEffect(() => {
    if (!searchBotMenuDomain) {
      searchBotMenuRef.current = null;
    }
  }, [searchBotMenuDomain]);

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

      const domainNames = new Set<string>();
      domainData.forEach((item) => domainNames.add(item.domain));
      overviewData.forEach((item) => domainNames.add(item.domain));
      if (searchBotMenuDomain && !domainNames.has(searchBotMenuDomain)) {
        setSearchBotMenuDomain(null);
      }
      const namesArray = Array.from(domainNames);
      const now = Date.now();
      const shouldPassiveRefresh =
        now - searchBotLastPassiveRef.current >= PASSIVE_SEARCHBOT_REFRESH_MS;

      if (!searchBotPrimed || shouldPassiveRefresh) {
        if (namesArray.length === 0) {
          setSearchBotPrimed(true);
          searchBotLastPassiveRef.current = now;
        } else {
          await primeSearchBotStats(namesArray);
        }
      } else if (namesArray.length > 0) {
        const missing = namesArray.filter(
          (name) => !searchBotStats[name.toLowerCase()],
        );
        if (missing.length > 0) {
          await Promise.allSettled(
            missing.map((name) =>
              fetchSearchBotStatsForDomain(name, { silent: true }),
            ),
          );
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

  const markWafUpdating = useCallback((domain: string, active: boolean) => {
    setWafUpdatingDomains((prev) => {
      const next = new Set(prev);
      const key = domain.toLowerCase();
      if (active) {
        next.add(key);
      } else {
        next.delete(key);
      }
      return next;
    });
  }, []);

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

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success("Copied to clipboard");
    } catch {
      toast.error("Failed to copy");
    }
  };

  const setSearchBotRefreshingFlag = useCallback((domainKey: string, value: boolean) => {
    setSearchBotRefreshing((prev) => {
      if (prev[domainKey] === value) {
        return prev;
      }
      return { ...prev, [domainKey]: value };
    });
  }, []);

  const isGooglebotOnlyEnabled = (record: Domain | DomainOverview): boolean => {
    const waf = record.waf;
    if (!waf || !waf.enabled) {
      return false;
    }
    if (!Array.isArray(waf.presets)) {
      return false;
    }
    return waf.presets.includes(GOOGLEBOT_WAF_PRESET);
  };

  const fetchSearchBotStatsForDomain = useCallback(
    async (
      domain: string,
      options?: { refresh?: boolean; silent?: boolean },
    ) => {
      if (searchBotAvailable === false) {
        return;
      }
      const refresh = options?.refresh ?? false;
      const silent = options?.silent ?? false;
      const key = domain.toLowerCase();
      if (!silent) {
        setSearchBotRefreshingFlag(key, true);
      }
      try {
        const data = await domainsApi.searchbots.stats(domain, refresh);
        setSearchBotStats((prev) => ({ ...prev, [key]: data }));
        if (searchBotAvailable !== true) {
          setSearchBotAvailable(true);
        }
      } catch (error: any) {
        const status = error?.response?.status;
        if (status === 404) {
          setSearchBotAvailable(false);
          setSearchBotStats({});
          setSearchBotRefreshing({});
          setSearchBotPrimed(true);
          if (!silent) {
            toast.error("Crawler logging extension is disabled");
          }
        } else if (!silent) {
          toast.error(`Failed to load crawler stats for ${domain}`);
        }
      } finally {
        if (!silent) {
          setSearchBotRefreshingFlag(key, false);
        }
      }
    },
    [searchBotAvailable, setSearchBotRefreshingFlag],
  );

  const primeSearchBotStats = useCallback(
    async (domainList: string[]) => {
      if (searchBotAvailable === false) {
        return;
      }
      if (domainList.length === 0) {
        searchBotLastPassiveRef.current = Date.now();
        setSearchBotPrimed(true);
        return;
      }
      await Promise.allSettled(
        domainList.map((domain) => fetchSearchBotStatsForDomain(domain, { silent: true })),
      );
      setSearchBotPrimed(true);
      searchBotLastPassiveRef.current = Date.now();
    },
    [fetchSearchBotStatsForDomain, searchBotAvailable],
  );

  const handleRefreshSearchBotStats = useCallback(
    async (domain: string) => {
      await fetchSearchBotStatsForDomain(domain, { refresh: true });
    },
    [fetchSearchBotStatsForDomain],
  );

  const handleExportSearchBotLogs = useCallback(
    async (domain: string, bot: string) => {
      const key = `${domain}|${bot}`;
      try {
        setSearchBotExporting(key);
        const blob = await domainsApi.searchbots.export(domain, bot);
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `${domain}-${bot}.log`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
        toast.success(`Exported ${bot.toUpperCase()} logs for ${domain}`);
      } catch (error: any) {
        const message =
          error?.response?.data?.error || `Failed to export logs for ${domain}`;
        toast.error(message);
      } finally {
        setSearchBotExporting(null);
      }
    },
    [],
  );

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
            <div className="ns-row-content">
              <span className="ns-host">{entry.name}</span>
              {showIPs && entry.ipv4 && <span className="ns-ip">{entry.ipv4}</span>}
            </div>
            <button
              className="ns-copy-btn"
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                const textToCopy = showIPs && entry.ipv4 
                  ? `${entry.name} ${entry.ipv4}`
                  : entry.name;
                copyToClipboard(textToCopy);
              }}
              title="Copy to clipboard"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
              </svg>
            </button>
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
        <Badge variant={meta.variant} size="sm" dot>
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
    return (record as any).edge_labels || [];
  };

  const buildEdgeModalData = (
    record: Domain | DomainOverview,
    override?: Domain,
  ): EdgeModalData => {
    const source = override ?? findFullDomain(record.domain);
    const assignedIp =
      override?.edge?.assigned_ip ??
      source?.edge?.assigned_ip ??
      ("edge" in record ? record.edge?.assigned_ip : (record as any).edge_ip);
    const nodeId =
      override?.edge?.assigned_node_id ??
      source?.edge?.assigned_node_id ??
      ("edge" in record ? record.edge?.assigned_node_id : (record as any).edge_node_id);
    const labels =
      override?.edge?.labels ??
      source?.edge?.labels ??
      ("edge" in record
        ? (record.edge?.labels ?? [])
        : ((record as any).edge_labels ?? []));
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
      origin_ip: originIp || "",
      proxied,
      ttl,
      labels,
      assigned_ip: assignedIp,
      node_id: nodeId,
      node_name: nodeName || undefined,
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
    const ipClass = info.proxied && info.assigned_ip ? "edge-ip-active" : "edge-ip-muted";
    const nodeSuffix =
      info.proxied && info.node_name ? ` (${info.node_name})` : "";
    return (
      <div className="edge-cell">
        <button
          className="edge-assignment-btn"
          onClick={() => openEdgeModal(record)}
          type="button"
        >
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
        </button>
        {info.labels.length > 0 && (
          <div className="edge-labels">
            {info.labels.map((label) => (
              <Badge
                key={`${record.domain}-edge-label-${label}`}
                variant="info"
                size="sm"
              >
                {label}
              </Badge>
            ))}
          </div>
        )}
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
          className="whois-manual-btn"
          onClick={(event) => {
            event.stopPropagation();
            handleManualWhois(record, whois);
          }}
          title="Set expiration manually"
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 20h9"/>
            <path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/>
          </svg>
        </button>
      </div>
    );
  };

  const handleToggleProxy = async (domain: Domain | DomainOverview) => {
    try {
      const domainName = domain.domain;
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
      const domainName = domain.domain;

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

  const handleToggleGooglebotOnly = async (
    domain: Domain | DomainOverview,
    nextState: boolean,
  ) => {
    const domainName = domain.domain;
    const domainKey = domainName.toLowerCase();
    const presetsSource = domain.waf?.presets ?? [];
    const currentPresets = Array.isArray(presetsSource)
      ? [...presetsSource]
      : [];
    let nextPresets: string[];
    if (nextState) {
      nextPresets = Array.from(
        new Set([...currentPresets, GOOGLEBOT_WAF_PRESET]),
      );
    } else {
      nextPresets = currentPresets.filter(
        (preset) => preset !== GOOGLEBOT_WAF_PRESET,
      );
    }
    const currentEnabled = domain.waf?.enabled ?? false;
    const nextEnabled = nextState
      ? true
      : nextPresets.length > 0 && currentEnabled;

    markWafUpdating(domainKey, true);
    try {
      const updated = await domainsApi.update(domainName, {
        waf: {
          enabled: nextEnabled,
          presets: nextPresets,
        },
      });

      setDomains((prev) =>
        prev.map((item) => (item.domain === domainName ? updated : item)),
      );

      setAllDomains((prev) =>
        prev.map((item) =>
          item.domain === domainName ? { ...item, waf: updated.waf } : item,
        ),
      );

      toast.success(
        nextState
          ? `Googlebot-only access enabled for ${domainName}`
          : `Googlebot-only access disabled for ${domainName}`,
      );

      loadData(false);
    } catch (error: any) {
      const message =
        error?.response?.data?.error ||
        `Failed to update WAF for ${domainName}`;
      toast.error(message);
    } finally {
      markWafUpdating(domainKey, false);
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
    const domainName = record.domain;
    const domainKey = domainName.toLowerCase();
    const isPurging = purgingDomain === domainName;
    const stats = searchBotStats[domainKey];
    const hasStats = Boolean(stats);
    const botEntries = SEARCHBOT_ALL_BOTS.map((bot) => {
      const source = stats?.bots?.find((item) => item.key === bot.key);
      const fallback: SearchBotBotStats = source ?? {
        key: bot.key,
        label: bot.label,
        icon: bot.icon,
        today: { current: 0, previous: 0, delta: 0 },
        month: { current: 0, previous: 0, delta: 0 },
        year: { current: 0, previous: 0, delta: 0 },
        total: 0,
      };
      return { definition: bot, stats: fallback };
    });
    const primaryBots = botEntries.filter(({ definition }) =>
      SEARCHBOT_PRIMARY_KEYS.includes(definition.key),
    );
    const showSearchBots =
      searchBotAvailable !== false && primaryBots.length > 0;
    const isRefreshingBots = !!searchBotRefreshing[domainKey];
    const generatedAt = stats?.generated_at
      ? new Date(stats.generated_at).toLocaleString()
      : undefined;
    const isMenuOpen = searchBotMenuDomain === domainName;
    const googlebotEnabled = isGooglebotOnlyEnabled(record);
    const wafBusy = wafUpdatingDomains.has(domainKey);
    const canUseWAF = record.proxied;
    const wafTitle = canUseWAF
      ? googlebotPresetDefinition?.description ??
        "Only verified Googlebot traffic is allowed when enabled"
      : "Enable proxying to enforce edge WAF presets";
    const formatCount = (value: number) =>
      value.toLocaleString(undefined, { maximumFractionDigits: 0 });

    return (
      <div className="domain-actions">
        <button
          type="button"
          className={`waf-toggle-btn${googlebotEnabled ? " waf-toggle-btn--active" : ""}`}
          onClick={(event) => {
            event.stopPropagation();
            if (wafBusy || !canUseWAF) {
              return;
            }
            handleToggleGooglebotOnly(record, !googlebotEnabled);
          }}
          title={wafTitle}
          disabled={wafBusy || !canUseWAF}
          aria-pressed={googlebotEnabled}
        >
          {wafBusy ? (
            <svg
              className="action-spinner"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path d="M21 12a9 9 0 11-6.219-8.56" />
            </svg>
          ) : (
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path d="M12 3l8 3v6c0 4.97-3.582 9.646-8 11-4.418-1.354-8-6.03-8-11V6l8-3z" />
              <path d="M12 8v6" />
              <path d="M9 11h6" />
            </svg>
          )}
        </button>
        {showSearchBots && (
          <div className="searchbot-actions">
            {primaryBots.map(({ definition, stats: botStats }) => {
              const exportKey = `${domainName}|${definition.key}`;
              const exporting = searchBotExporting === exportKey;
              const canExport = hasStats && !exporting;
              return (
                <div className="searchbot-bot" key={definition.key}>
                  <button
                    type="button"
                    className={`searchbot-counts${
                      isRefreshingBots ? " searchbot-counts--loading" : ""
                    }`}
                    onClick={(event) => {
                      event.stopPropagation();
                      if (!isRefreshingBots) {
                        handleRefreshSearchBotStats(domainName);
                      }
                    }}
                    disabled={isRefreshingBots}
                    title={
                      hasStats && generatedAt
                        ? `Updated ${generatedAt}. Click to refresh.`
                        : "Click to refresh crawler stats"
                    }
                  >
                    {SEARCHBOT_PERIODS.map((period) => {
                      const periodStats = botStats[period.key];
                      const delta =
                        hasStats && periodStats.delta !== 0
                          ? periodStats.delta
                          : null;
                      const displayValue = hasStats
                        ? formatCount(periodStats.current)
                        : "—";
                      return (
                        <span className="searchbot-count" key={period.key}>
                          <span className="searchbot-count-label">
                            {period.short}
                          </span>
                          <strong>{displayValue}</strong>
                          {delta !== null && (
                            <span
                              className={`searchbot-delta ${
                                delta > 0
                                  ? "searchbot-delta--positive"
                                  : "searchbot-delta--negative"
                              }`}
                            >
                              {delta > 0 ? `+${delta}` : delta}
                            </span>
                          )}
                        </span>
                      );
                    })}
                  </button>
                  <button
                    type="button"
                    className="searchbot-export"
                    onClick={(event) => {
                      event.stopPropagation();
                      if (canExport) {
                        handleExportSearchBotLogs(domainName, definition.key);
                      }
                    }}
                    disabled={!canExport}
                    title={`Export ${definition.label} logs`}
                  >
                    {exporting ? (
                      <svg
                        className="action-spinner"
                        width="14"
                        height="14"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                      >
                        <path d="M21 12a9 9 0 11-6.219-8.56"/>
                      </svg>
                    ) : (
                      <span>
                        {definition.icon ??
                          definition.key.slice(0, 1).toUpperCase()}
                      </span>
                    )}
                  </button>
                </div>
              );
            })}
            <div className="searchbot-menu-container">
              <button
                type="button"
                className="searchbot-menu-trigger"
                onClick={(event) => {
                  event.stopPropagation();
                  setSearchBotMenuDomain((prev) =>
                    prev === domainName ? null : domainName,
                  );
                }}
                title="View crawler details"
              >
                ⋯
              </button>
              {isMenuOpen && (
                <div className="searchbot-menu" ref={searchBotMenuRef}>
                  <div className="searchbot-menu-list">
                    {botEntries.map(({ definition, stats: botStats }) => {
                      const exportKey = `${domainName}|${definition.key}`;
                      const exporting = searchBotExporting === exportKey;
                      const canExport = hasStats && !exporting;
                      return (
                        <div className="searchbot-menu-item" key={definition.key}>
                          <div className="searchbot-menu-item-info">
                            <div className="searchbot-menu-item-head">
                              <span className="searchbot-menu-item-icon">
                                {definition.icon ??
                                  definition.key.slice(0, 1).toUpperCase()}
                              </span>
                              <span className="searchbot-menu-item-label">
                                {botStats.label}
                              </span>
                            </div>
                            <div className="searchbot-menu-metrics">
                              {SEARCHBOT_PERIODS.map((period) => (
                                <span key={period.key}>
                                  {period.label}:{" "}
                                  {formatCount(botStats[period.key].current)}
                                </span>
                              ))}
                              <span>Total: {formatCount(botStats.total)}</span>
                            </div>
                          </div>
                          <button
                            type="button"
                            className="searchbot-menu-export"
                            title={`Export ${definition.label} logs`}
                            disabled={!canExport}
                            onClick={async (event) => {
                              event.stopPropagation();
                              if (!canExport) {
                                return;
                              }
                              await handleExportSearchBotLogs(
                                domainName,
                                definition.key,
                              );
                              setSearchBotMenuDomain(null);
                            }}
                          >
                            {exporting ? (
                              <svg
                                className="action-spinner"
                                width="14"
                                height="14"
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                                strokeWidth="2"
                              >
                                <path d="M21 12a9 9 0 11-6.219-8.56" />
                              </svg>
                            ) : (
                              <span>
                                {definition.icon ??
                                  definition.key.slice(0, 1).toUpperCase()}
                              </span>
                            )}
                          </button>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
        <button
          className="action-btn"
          type="button"
          onClick={() => handlePurgeCache(domainName)}
          disabled={isPurging}
          title="Purge cache"
        >
          {isPurging ? (
            <svg
              className="action-spinner"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path d="M21 12a9 9 0 11-6.219-8.56"/>
            </svg>
          ) : (
            <svg width="16" height="16" viewBox="0 0 32 32" fill="currentColor">
              <path d="M 28.28125 2.28125 L 18.28125 12.28125 L 17 11 L 17 10.96875 L 16.96875 10.9375 C 16.328125 10.367188 15.492188 10.09375 14.6875 10.09375 C 13.882813 10.09375 13.105469 10.394531 12.5 11 L 12.34375 11.125 L 11.84375 11.625 L 11.5 11.90625 L 2.375 19 L 1.5 19.71875 L 12.28125 30.5 L 13 29.625 L 20.0625 20.5625 L 20.09375 20.59375 L 21.09375 19.59375 L 21.125 19.59375 L 21.15625 19.5625 C 22.296875 18.277344 22.304688 16.304688 21.09375 15.09375 L 19.71875 13.71875 L 29.71875 3.71875 Z M 14.6875 12.09375 C 14.996094 12.085938 15.335938 12.191406 15.59375 12.40625 C 15.605469 12.414063 15.613281 12.429688 15.625 12.4375 L 19.6875 16.5 C 20.0625 16.875 20.097656 17.671875 19.6875 18.1875 C 19.671875 18.207031 19.671875 18.230469 19.65625 18.25 L 19.34375 18.53125 L 13.5625 12.75 L 13.90625 12.40625 C 14.097656 12.214844 14.378906 12.101563 14.6875 12.09375 Z M 12.03125 14.03125 L 17.96875 19.96875 L 12.09375 27.46875 L 10.65625 26.03125 L 12.8125 23.78125 L 11.375 22.40625 L 9.25 24.625 L 7.9375 23.3125 L 11.8125 19.40625 L 10.40625 18 L 6.5 21.875 L 4.53125 19.90625 Z"/>
            </svg>
          )}
        </button>
      </div>
    );
  };

  const handleEditIP = (domain: Domain | DomainOverview) => {
    const domainName = domain.domain;
    setEditingDomain(domainName);
    const current = (domain as any).origin_ip ?? "";
    setEditingIP(typeof current === "string" ? current : "");
    setTimeout(() => editInputRef.current?.select(), 0);
  };

  const handleSaveIP = async (domain: Domain | DomainOverview) => {
    const domainName = domain.domain;

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

    const domainWord = selectedDomains.size === 1 ? 'domain' : 'domains';
    const confirmMessage = `Are you sure you want to permanently delete ${selectedDomains.size} ${domainWord}?\n\nThis action cannot be undone.\n\nDomains to be deleted:\n${Array.from(selectedDomains).slice(0, 5).join('\n')}${selectedDomains.size > 5 ? `\n...and ${selectedDomains.size - 5} more` : ''}`;
    
    if (!window.confirm(confirmMessage)) return;

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
        <div className="tls-display-compact">
          <div className="tls-select-wrapper">
            <select
              className="tls-mode-select-compact"
              value={currentValue}
              onChange={(e) => canEdit && handleChangeTLS(domain, e.target.value)}
              disabled={!domain.proxied || !canEdit}
            >
              <option value="off">Off</option>
              <option value="flexible">Flexible</option>
              <option value="full">Full</option>
              <option value="full_strict">Strict</option>
              <option value="auto">Auto</option>
            </select>
            {domain.tls_use_recommended && (
              <span className="tls-auto-subtitle">
                → {domain.tls_recommended_mode
                  ? modeLabel(domain.tls_recommended_mode)
                  : "detecting"}
              </span>
            )}
          </div>
          <div className="tls-status-indicator">
            {statusKey !== "none" && (
              <span 
                className={`tls-status-dot tls-status-dot--${statusKey}`}
                title={domain.tls_last_error || retryHint || statusKey}
              />
            )}
          </div>
        </div>
      );
    }

    // Full Domain with complete TLS data
    const statusKey = domain.tls.status || "none";
    const currentValue = domain.tls.use_recommended ? "auto" : domain.tls.mode;
    const retryHint = computeRetryHint(domain.tls.retry_after);

    return (
      <div className="tls-display-compact">
        <div className="tls-select-wrapper">
          <select
            className="tls-mode-select-compact"
            value={currentValue}
            onChange={(e) => handleChangeTLS(domain, e.target.value)}
            disabled={!domain.proxied}
          >
            <option value="off">Off</option>
            <option value="flexible">Flexible</option>
            <option value="full">Full</option>
            <option value="full_strict">Strict</option>
            <option value="auto">Auto</option>
          </select>
          {domain.tls.use_recommended && (
            <span className="tls-auto-subtitle">
              → {domain.tls.recommended_mode
                ? modeLabel(domain.tls.recommended_mode)
                : "detecting"}
            </span>
          )}
        </div>
        <div className="tls-status-indicator">
          {statusKey !== "none" && (
            <span 
              className={`tls-status-dot tls-status-dot--${statusKey}`}
              title={domain.tls.last_error || retryHint || statusKey}
            />
          )}
        </div>
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
          (d.origin_ip || "").includes(searchQuery)) &&
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
  const referenceDomains = useMemo<DomainLike[]>(() => {
    const combined = new Map<string, DomainLike>();
    domains.forEach((record) => combined.set(record.domain, record));
    allDomains.forEach((record) => combined.set(record.domain, record));
    return Array.from(combined.values());
  }, [domains, allDomains]);

  const tableData = useMemo(() => {
    return buildDomainRows(filteredData as DomainLike[]);
  }, [filteredData]);

  const primaryDomainOptions = useMemo(() => {
    const seen = new Set<string>();
    const entries: string[] = [];
    referenceDomains.forEach((record) => {
      const role = record.role ?? "primary";
      if (role === "primary" && !seen.has(record.domain)) {
        seen.add(record.domain);
        entries.push(record.domain);
      }
    });
    return entries.sort((a, b) => a.localeCompare(b));
  }, [referenceDomains]);

  const openRoleModal = (row: DomainWithMeta, mode: 'alias' | 'redirect' | 'primary') => {
    setRoleModalState({ domain: row, mode });
  };

  const handleOpenRedirectRulesModal = (row: DomainWithMeta) => {
    setRedirectRulesModalDomain(row);
  };

  const handleRemoveAlias = async (row: DomainWithMeta) => {
    const parentDomain = row.__meta.parentDomain || 'unknown';
    const confirmMessage = `Are you sure you want to remove the alias relationship?\n\n${row.domain} will no longer be an alias of ${parentDomain}.\n\nThis domain will become a standalone primary domain.`;
    
    if (!window.confirm(confirmMessage)) {
      return;
    }
    
    try {
      await domainsApi.update(row.domain, {
        role: 'primary',
        alias: null,
        redirect_rules: [],
      });
      toast.success(`${row.domain} converted to primary domain`);
      await loadData();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to remove alias');
    }
  };

  const handleRemoveRedirect = async (row: DomainWithMeta) => {
    const redirectTarget = row.__meta.redirectTarget || 'unknown';
    const confirmMessage = `Are you sure you want to remove the redirect?\n\n${row.domain} will no longer redirect to ${redirectTarget}.\n\nThis domain will become a standalone primary domain.`;
    
    if (!window.confirm(confirmMessage)) {
      return;
    }
    
    try {
      await domainsApi.update(row.domain, {
        role: 'primary',
        alias: null,
        redirect_rules: [],
      });
      toast.success(`${row.domain} converted to primary domain`);
      await loadData();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to remove redirect');
    }
  };

  const formatRedirectTarget = (target?: string, external?: boolean) => {
    if (!target) {
      return '—';
    }
    return target;
  };

  const renderDomainCell = (row: DomainWithMeta) => {
    const meta = row.__meta;
    const ownerMissing = (row as DomainOverview).owner_exists === false;
    const isAlias = meta.position === 'alias';
    const isRedirect = meta.position === 'redirect';
    const isParent = meta.position === 'parent';
    const hasChildren = (meta.aliasChildren.length > 0) || (meta.redirectChildren.length > 0);
    const domainRule = meta.domainRule;
    const pathRules = meta.pathRules ?? [];
    const pathRulesInactive = Boolean(domainRule) && isParent;

    const handleAction = (event: React.MouseEvent, callback: () => void) => {
      event.stopPropagation();
      callback();
    };

    const aliasChips = isParent && meta.aliasChildren.length > 0 && (
      <div className="domain-chip-inline">
        <span className="domain-icon-prefix">+</span>
        {meta.aliasChildren.map((child, idx) => (
          <React.Fragment key={`alias-${child.domain}`}>
            <span className="domain-chip domain-chip-alias-minimal">
              <span className="domain-chip-label">{child.domain}</span>
              <span className="domain-chip-actions">
                <button
                  type="button"
                  onClick={(e) => handleAction(e, () => openRoleModal(child, 'alias'))}
                  title="Edit alias"
                >
                  ✎
                </button>
                <button
                  type="button"
                  onClick={(e) => handleAction(e, () => handleRemoveAlias(child))}
                  title="Remove alias"
                >
                  ✕
                </button>
              </span>
            </span>
            {idx < meta.aliasChildren.length - 1 && <span className="domain-chip-separator">,</span>}
          </React.Fragment>
        ))}
      </div>
    );

    const redirectChips = isParent && meta.redirectChildren.length > 0 && (
      <div className="domain-chip-inline">
        <span className="domain-icon-prefix">↖</span>
        {meta.redirectChildren.map((child, idx) => (
          <React.Fragment key={`redirect-${child.domain}`}>
            <span className="domain-chip domain-chip-redirect-minimal">
              <span className="domain-chip-label">{child.domain}</span>
              {child.__meta.redirectTarget !== row.domain && (
                <>
                  <span className="domain-chip-arrow">→</span>
                  <span className="domain-chip-secondary">
                    {formatRedirectTarget(child.__meta.redirectTarget, child.__meta.redirectExternal)}
                  </span>
                </>
              )}
              <span className="domain-chip-actions">
                <button
                  type="button"
                  onClick={(e) => handleAction(e, () => openRoleModal(child, 'redirect'))}
                  title="Edit redirect"
                >
                  ✎
                </button>
                <button
                  type="button"
                  onClick={(e) => handleAction(e, () => handleRemoveRedirect(child))}
                  title="Remove redirect"
                >
                  ✕
                </button>
              </span>
            </span>
            {idx < meta.redirectChildren.length - 1 && <span className="domain-chip-separator">,</span>}
          </React.Fragment>
        ))}
      </div>
    );

    let subtitle: React.ReactNode = null;
    if (isAlias) {
      subtitle = (
        <span className="domain-label domain-label-alias">
          <span className="domain-icon-plus">+</span> {meta.parentDomain ?? 'unknown'}
        </span>
      );
    } else if (isRedirect) {
      // Check if redirecting to the parent domain
      const redirectToParent = meta.parentDomain && 
        (meta.redirectTarget === meta.parentDomain || 
         meta.redirectTarget === `https://${meta.parentDomain}` ||
         meta.redirectTarget === `http://${meta.parentDomain}`);
      const redirectIcon = redirectToParent ? '↖' : '→';
      subtitle = (
        <span className="domain-label domain-label-redirect">
          <span className="domain-icon-arrow">{redirectIcon}</span> {formatRedirectTarget(meta.redirectTarget, meta.redirectExternal)}
        </span>
      );
    }

    // Only apply visual indicators if domain has relationships
    const cellClassName = hasChildren || isAlias || isRedirect
      ? `domain-cell domain-cell-${meta.position}` 
      : 'domain-cell';
      
    return (
      <div className={cellClassName}>
        <div className="domain-header">
          <div className="domain-title">
            <span className="domain-name mono">{row.domain}</span>
            {ownerMissing && (
              <Badge variant="warning" size="sm">
                Orphaned
              </Badge>
            )}
          </div>
          <div className="domain-inline-actions">
            <button
              type="button"
              className="domain-inline-button"
              onClick={(e) => handleAction(e, () => openRoleModal(row, 'alias'))}
              title="Configure alias"
            >
              ＋
            </button>
            {!isAlias && (
              <button
                type="button"
                className="domain-inline-button"
                onClick={(e) => handleAction(e, () => handleOpenRedirectRulesModal(row))}
                title="Manage redirect rules"
              >
                ↷
              </button>
            )}
          </div>
        </div>
        {subtitle && <div className="domain-subtitle">{subtitle}</div>}
        {domainRule && isParent && (
          <div className="domain-redirect-summary">
            <span className="domain-redirect-icon">→</span>
            <strong>{formatRedirectTarget(domainRule.target, domainRule.target?.includes('://'))}</strong>
            {(domainRule.preserve_path || !domainRule.preserve_query) && (
              <span className="domain-redirect-flags">
                {domainRule.preserve_path && <span className="domain-redirect-flag">+path</span>}
                {!domainRule.preserve_query && <span className="domain-redirect-flag">-query</span>}
              </span>
            )}
          </div>
        )}
        {aliasChips}
        {redirectChips}
        {pathRules.length > 0 && (
          <div className={`path-redirect-list${pathRulesInactive ? ' inactive' : ''}`}>
            {pathRulesInactive && (
              <div className="path-redirect-warning">
                <span className="warning-icon">⚠</span>
                Path redirects inactive (domain-level redirect active)
              </div>
            )}
            {pathRules.map((rule) => (
              <div key={`${rule.id || rule.source}`} className="path-redirect-item">
                <span className="path-redirect-arrow">⇢</span>
                <code className="path-redirect-source">{rule.source}</code>
                <span className="path-redirect-target">→ {rule.target}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };
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
    accessor: (row: DomainWithMeta) => renderDomainCell(row),
  });

  columns.push({
    key: "nameservers",
    header: "Nameservers",
    accessor: (d: any) => renderNameserverCell(d),
    width: "320px",
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
            {isPlaceholder ? "placeholder" : displayValue}
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
    width: "100px",
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
    width: "140px",
  });

  columns.push({
    key: "actions",
    header: "",
    accessor: (d: any) => renderDomainActions(d),
    width: "50px",
    align: "center" as const,
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

      <div className="domains-table-group">
        {selectionEnabled && tableData.length > 0 && (
          <div className="global-selection-controls">
            <label className="global-select-all">
              <input
                type="checkbox"
                checked={selectedDomains.size === tableData.length && tableData.length > 0}
                onChange={(e) => {
                  if (e.target.checked) {
                    setSelectedDomains(new Set(tableData.map(d => d.domain)));
                  } else {
                    setSelectedDomains(new Set());
                  }
                }}
              />
              <span>Select all {tableData.length} domains</span>
            </label>
            {selectedDomains.size > 0 && selectedDomains.size < tableData.length && (
              <span className="partial-selection-info">
                {selectedDomains.size} of {tableData.length} selected
              </span>
            )}
            {selectedDomains.size > 0 && (
              <button
                className="clear-selection-btn"
                onClick={() => setSelectedDomains(new Set())}
                type="button"
              >
                Clear selection
              </button>
            )}
          </div>
        )}
        {(() => {
          // Group table data by families
          const familyGroups: DomainWithMeta[][] = [];
          const processedDomains = new Set<string>();
          
          tableData.forEach((domain) => {
            if (processedDomains.has(domain.domain)) return;
            
            const group: DomainWithMeta[] = [];
            
            // If it's a parent with children
            if (domain.__meta.aliasChildren.length > 0 || domain.__meta.redirectChildren.length > 0) {
              group.push(domain);
              processedDomains.add(domain.domain);
              
              [...domain.__meta.aliasChildren, ...domain.__meta.redirectChildren].forEach(child => {
                if (tableData.find(d => d.domain === child.domain)) {
                  group.push(child);
                  processedDomains.add(child.domain);
                }
              });
            }
            // If it's an alias or redirect that wasn't processed yet
            else if (domain.__meta.position === 'alias' || domain.__meta.position === 'redirect') {
              // Find its parent if exists in tableData
              const parent = tableData.find(d => d.domain === domain.__meta.parentDomain);
              if (parent && !processedDomains.has(parent.domain)) {
                group.push(parent);
                processedDomains.add(parent.domain);
                
                [...parent.__meta.aliasChildren, ...parent.__meta.redirectChildren].forEach(child => {
                  if (tableData.find(d => d.domain === child.domain)) {
                    group.push(child);
                    processedDomains.add(child.domain);
                  }
                });
              } else if (!parent || processedDomains.has(parent.domain)) {
                // Orphaned alias/redirect or parent already processed
                if (!processedDomains.has(domain.domain)) {
                  group.push(domain);
                  processedDomains.add(domain.domain);
                }
              }
            }
            // Standalone domain
            else if (domain.__meta.position === 'standalone' || domain.__meta.position === 'parent') {
              group.push(domain);
              processedDomains.add(domain.domain);
            }
            
            if (group.length > 0) {
              familyGroups.push(group);
            }
          });
          
          if (loading) {
            return (
              <Card className="domains-card" padding="none">
                <Table
                  columns={columns}
                  data={[]}
                  keyExtractor={(d: DomainWithMeta) => d.domain}
                  loading={true}
                  emptyMessage="Loading domains..."
                />
              </Card>
            );
          }
          
          if (familyGroups.length === 0) {
            return (
              <Card className="domains-card" padding="none">
                <Table
                  columns={columns}
                  data={[]}
                  keyExtractor={(d: DomainWithMeta) => d.domain}
                  loading={false}
                  emptyMessage="No domains found"
                />
              </Card>
            );
          }
          
          return familyGroups.map((group, index) => (
            <Card key={`group-${index}-${group[0]?.domain}`} className="domains-card domain-group-card" padding="none">
              <Table
                columns={columns}
                data={group}
                keyExtractor={(d: DomainWithMeta) => d.domain}
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
                        const newSelected = new Set(selectedDomains);
                        if (selected) {
                          group.forEach(row => newSelected.add(row.domain));
                        } else {
                          group.forEach(row => newSelected.delete(row.domain));
                        }
                        setSelectedDomains(newSelected);
                      }
                    : undefined
                }
                rowClassName={(row) => {
                  const meta = row.__meta;
                  const classes: string[] = [];
                  
                  // Add family color class only for parent rows
                  const isParent = meta.position === 'parent';
                  if (isParent && meta.familyIndex !== undefined) {
                    classes.push(`table-row-family-${meta.familyIndex % 6}`);
                    classes.push('table-row-parent');
                  }
                  
                  // Add family member class for all related domains
                  const isInFamily = meta.familyId && (
                    meta.position === 'alias' || 
                    meta.position === 'redirect' || 
                    meta.aliasChildren.length > 0 || 
                    meta.redirectChildren.length > 0
                  );
                  if (isInFamily) {
                    classes.push('table-row-family-member');
                  }
                  
                  return classes.length > 0 ? classes.join(' ') : undefined;
                }}
                loading={false}
                emptyMessage="No domains found"
              />
            </Card>
          ));
        })()}
      </div>

      {nameservers.length > 0 && (
        <Card className="nameservers-card" title="Nameservers">
          <div className="nameservers-list">
            {nameservers.map((ns) => (
              <div key={ns.node_id} className="nameserver-item">
                <span className="ns-fqdn mono">{ns.fqdn}</span>
                <button
                  className="ns-copy-btn"
                  type="button"
                  onClick={() => copyToClipboard(ns.fqdn)}
                  title="Copy to clipboard"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                    <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
                  </svg>
                </button>
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
      {roleModalState && (
        <DomainRoleModal
          domain={roleModalState.domain}
          mode={roleModalState.mode}
          primaryOptions={primaryDomainOptions}
          onClose={() => setRoleModalState(null)}
          onSaved={() => {
            setRoleModalState(null);
            loadData();
          }}
        />
      )}
      {redirectRulesModalDomain && (
        <RedirectRulesModal
          domain={redirectRulesModalDomain}
          onClose={() => setRedirectRulesModalDomain(null)}
          onSaved={() => {
            setRedirectRulesModalDomain(null);
            loadData();
          }}
        />
      )}
    </div>
  );
}

function splitRedirectRules(record: DomainLike): {
  domainRule: DomainRedirectRule | null;
  pathRules: DomainRedirectRule[];
} {
  const rules = record.redirect_rules ?? [];
  let domainRule: DomainRedirectRule | null = null;
  const pathRules: DomainRedirectRule[] = [];
  rules.forEach((rule) => {
    const source = rule.source?.trim() ?? "";
    if (source === "") {
      domainRule = rule;
      return;
    }
    if (source.startsWith("/")) {
      pathRules.push(rule);
    }
  });
  return { domainRule, pathRules };
}

function computeExpiryTimestamp(record: DomainLike): number {
  const expiresAt = record.whois?.expires_at;
  if (!expiresAt) {
    return Number.POSITIVE_INFINITY;
  }
  const ts = Date.parse(expiresAt);
  if (Number.isNaN(ts)) {
    return Number.POSITIVE_INFINITY;
  }
  return ts;
}

function compareByExpiry(a: DomainLike, b: DomainLike): number {
  const tsA = computeExpiryTimestamp(a);
  const tsB = computeExpiryTimestamp(b);
  if (tsA === tsB) {
    return a.domain.localeCompare(b.domain);
  }
  if (tsA === Number.POSITIVE_INFINITY) {
    return 1;
  }
  if (tsB === Number.POSITIVE_INFINITY) {
    return -1;
  }
  return tsA - tsB;
}

function buildDomainRows(records: DomainLike[]): DomainWithMeta[] {
  const clones: DomainWithMeta[] = records.map((record) => {
    const cloned = { ...(record as any) } as DomainLike;
    const { domainRule, pathRules } = splitRedirectRules(cloned);
    const meta: DomainRowMeta = {
      position: 'standalone',
      aliasChildren: [],
      redirectChildren: [],
      domainRule,
      pathRules: [...pathRules],
      parentDomain: undefined,
      familyId: undefined,
      familyIndex: undefined,
      redirectTarget: domainRule?.target,
      redirectExternal: false,
    };
    return { ...(cloned as any), __meta: meta } as DomainWithMeta;
  });

  const recordMap = new Map<string, DomainWithMeta>();
  clones.forEach((record) => {
    recordMap.set(record.domain, record);
  });

  const families = new Map<string, { parent?: DomainWithMeta; aliases: DomainWithMeta[]; redirects: DomainWithMeta[] }>();

  clones.forEach((record) => {
    const role: DomainRole = record.role ?? 'primary';
    const meta = record.__meta;
    if (role === 'alias' && record.alias?.target) {
      const target = record.alias.target;
      const parent = recordMap.get(target);
      meta.position = 'alias';
      meta.parentDomain = target;
      if (parent) {
        let family = families.get(parent.domain);
        if (!family) {
          family = { parent, aliases: [], redirects: [] };
          families.set(parent.domain, family);
        } else if (!family.parent) {
          family.parent = parent;
        }
        family.aliases.push(record);
        parent.__meta.aliasChildren.push(record);
      } else {
        families.set(record.domain, { parent: record, aliases: [], redirects: [] });
      }
    } else if (role === 'redirect') {
      const { domainRule } = splitRedirectRules(record);
      const target = domainRule?.target?.trim() ?? '';
      const normalized = target.toLowerCase();
      meta.position = 'redirect';
      meta.redirectTarget = target;
      const parent = normalized ? recordMap.get(normalized) : undefined;
      const isInternal = !!parent && (parent.role ?? 'primary') === 'primary';
      meta.redirectExternal = !isInternal && !!target && target.includes('://');
      if (isInternal && parent) {
        meta.parentDomain = parent.domain;
        let family = families.get(parent.domain);
        if (!family) {
          family = { parent, aliases: [], redirects: [] };
          families.set(parent.domain, family);
        } else if (!family.parent) {
          family.parent = parent;
        }
        family.redirects.push(record);
        parent.__meta.redirectChildren.push(record);
      } else {
        families.set(record.domain, { parent: record, aliases: [], redirects: [] });
      }
    } else {
      // Don't set position to 'parent' yet - will determine later based on children
      let family = families.get(record.domain);
      if (!family) {
        family = { parent: record, aliases: [], redirects: [] };
        families.set(record.domain, family);
      } else if (!family.parent) {
        family.parent = record;
      }
    }
  });

  families.forEach((family) => {
    if (family.parent) {
      family.parent.__meta.aliasChildren = family.aliases;
      family.parent.__meta.redirectChildren = family.redirects;
      
      // Only set position to 'parent' if it has children and is not already an alias/redirect
      if (family.parent.__meta.position === 'standalone') {
        if (family.aliases.length > 0 || family.redirects.length > 0) {
          family.parent.__meta.position = 'parent';
        }
        // else leave it as 'standalone' - it's a domain without relationships
      }
    }
  });

  const familyList = Array.from(families.values());
  familyList.sort((a, b) => {
    const aMembers = [a.parent, ...a.aliases, ...a.redirects].filter(Boolean) as DomainLike[];
    const bMembers = [b.parent, ...b.aliases, ...b.redirects].filter(Boolean) as DomainLike[];
    const aExpiry = aMembers.length > 0 ? Math.min(...aMembers.map(computeExpiryTimestamp)) : Number.POSITIVE_INFINITY;
    const bExpiry = bMembers.length > 0 ? Math.min(...bMembers.map(computeExpiryTimestamp)) : Number.POSITIVE_INFINITY;
    if (aExpiry === bExpiry) {
      const aName = a.parent?.domain ?? a.aliases[0]?.domain ?? a.redirects[0]?.domain ?? '';
      const bName = b.parent?.domain ?? b.aliases[0]?.domain ?? b.redirects[0]?.domain ?? '';
      return aName.localeCompare(bName);
    }
    if (aExpiry === Number.POSITIVE_INFINITY) {
      return 1;
    }
    if (bExpiry === Number.POSITIVE_INFINITY) {
      return -1;
    }
    return aExpiry - bExpiry;
  });

  const rows: DomainWithMeta[] = [];
  familyList.forEach((family, index) => {
    const familyIndex = index % 6;
    const familyMembers: DomainWithMeta[] = [];
    
    // Collect all family members
    if (family.parent) {
      familyMembers.push(family.parent);
      const sortedAliases = family.aliases.slice().sort((a, b) => compareByExpiry(a, b));
      familyMembers.push(...sortedAliases);
      const sortedRedirects = family.redirects.slice().sort((a, b) => compareByExpiry(a, b));
      familyMembers.push(...sortedRedirects);
    }
    
    // Assign family position to each member
    familyMembers.forEach((member, idx) => {
      member.__meta.familyIndex = familyIndex;
      member.__meta.familyId = family.parent?.domain ?? member.domain;
      
      if (familyMembers.length === 1) {
        member.__meta.familyPosition = 'single';
      } else if (idx === 0) {
        member.__meta.familyPosition = 'first';
      } else if (idx === familyMembers.length - 1) {
        member.__meta.familyPosition = 'last';
      } else {
        member.__meta.familyPosition = 'middle';
      }
      
      rows.push(member);
    });
    
    if (familyMembers.length === 0 && (family.aliases.length > 0 || family.redirects.length > 0)) {
      const standaloneMembers = [...family.aliases, ...family.redirects];
      const sortedMembers = standaloneMembers.slice().sort((a, b) => compareByExpiry(a, b));
      sortedMembers.forEach((member) => {
        member.__meta.familyIndex = familyIndex;
        member.__meta.familyId = member.domain;
        member.__meta.familyPosition = 'single';
        rows.push(member);
      });
    }
  });

  return rows;
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
          value={formData.origin_ip || ""}
          onChange={(e) =>
            setFormData({ ...formData, origin_ip: e.target.value })
          }
          fullWidth
        />
        <p className="form-hint">
          Leave blank for aki.cloud placeholder
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

interface DomainRoleModalProps {
  domain: DomainWithMeta;
  mode: 'alias' | 'redirect' | 'primary';
  onClose: () => void;
  onSaved: () => void;
  primaryOptions: string[];
}

function DomainRoleModal({ domain, mode, onClose, onSaved, primaryOptions }: DomainRoleModalProps) {
  const modalRef = useRef<HTMLDivElement>(null);
  const [isMouseDown, setIsMouseDown] = useState(false);
  const [loading, setLoading] = useState(false);

  const availablePrimarySet = new Set<string>();
  primaryOptions.forEach((option) => {
    if (option !== domain.domain) {
      availablePrimarySet.add(option);
    }
  });
  if (domain.alias?.target) {
    availablePrimarySet.add(domain.alias.target);
  }
  const availablePrimaries = Array.from(availablePrimarySet);

  const initialAliasTarget = domain.alias?.target ?? availablePrimaries[0] ?? '';
  const [aliasTarget, setAliasTarget] = useState(initialAliasTarget);

  const existingDomainRule = domain.__meta.domainRule;
  const [redirectTarget, setRedirectTarget] = useState(existingDomainRule?.target ?? '');
  const [redirectStatus, setRedirectStatus] = useState(existingDomainRule?.status_code ?? 301);
  const [redirectPreservePath, setRedirectPreservePath] = useState(existingDomainRule?.preserve_path ?? false);
  const [redirectPreserveQuery, setRedirectPreserveQuery] = useState(
    existingDomainRule ? existingDomainRule.preserve_query : true,
  );

  const handleMouseDown = (event: React.MouseEvent) => {
    if (!modalRef.current?.contains(event.target as Node)) {
      setIsMouseDown(true);
    }
  };

  const handleMouseUp = (event: React.MouseEvent) => {
    if (isMouseDown && !modalRef.current?.contains(event.target as Node)) {
      onClose();
    }
    setIsMouseDown(false);
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    try {
      if (mode === 'alias') {
        if (!aliasTarget) {
          toast.error('Select a primary domain to alias');
          setLoading(false);
          return;
        }
        await domainsApi.update(domain.domain, {
          role: 'alias',
          alias: { target: aliasTarget },
          redirect_rules: [],
        });
        toast.success(`${domain.domain} now aliases ${aliasTarget}`);
      } else if (mode === 'redirect') {
        const target = redirectTarget.trim();
        if (!target) {
          toast.error('Redirect target is required');
          setLoading(false);
          return;
        }
        const rule: DomainRedirectRule = {
          id: existingDomainRule?.id ?? '',
          source: '',
          target,
          status_code: redirectStatus,
          preserve_path: redirectPreservePath,
          preserve_query: redirectPreserveQuery,
        };
        await domainsApi.update(domain.domain, {
          role: 'redirect',
          redirect_rules: [rule],
        });
        toast.success(`${domain.domain} now redirects to ${target}`);
      } else {
        const pathRules = domain.__meta.pathRules ?? [];
        await domainsApi.update(domain.domain, {
          role: 'primary',
          alias: null,
          redirect_rules: pathRules,
        });
        toast.success(`${domain.domain} converted to primary`);
      }
      onSaved();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to update domain role');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onMouseDown={handleMouseDown} onMouseUp={handleMouseUp}>
      <div className="modal" ref={modalRef}>
        <header className="modal-header">
          <h2>
            {mode === 'alias' && `Alias ${domain.domain}`}
            {mode === 'redirect' && `Redirect ${domain.domain}`}
            {mode === 'primary' && `Set ${domain.domain} to primary`}
          </h2>
          <button type="button" className="modal-close" onClick={onClose}>
            ×
          </button>
        </header>
        <form className="modal-body" onSubmit={handleSubmit}>
          {mode === 'alias' && (
            <div className="modal-section">
              <div className="form-group">
                <label>Primary target domain</label>
                {availablePrimaries.length === 0 ? (
                  <p className="form-hint">No primary domains available. Please add a primary domain first.</p>
                ) : (
                  <>
                    <select
                      className="form-select"
                      value={aliasTarget}
                      onChange={(e) => setAliasTarget(e.target.value)}
                      required
                    >
                      <option value="" disabled>
                        Select primary domain
                      </option>
                      {availablePrimaries.map((option) => (
                        <option key={option} value={option}>
                          {option}
                        </option>
                      ))}
                    </select>
                    <p className="form-hint">
                      This domain will serve the same content as the selected primary domain
                    </p>
                  </>
                )}
              </div>
            </div>
          )}
          {mode === 'redirect' && (
            <div className="modal-section">
              <div className="form-group">
                <label>Redirect target URL</label>
                <input
                  className="form-input"
                  value={redirectTarget}
                  onChange={(e) => setRedirectTarget(e.target.value)}
                  placeholder="https://example.com or another-domain.com"
                  required
                />
                <p className="form-hint">
                  Enter the destination URL (external) or domain name (internal)
                </p>
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label>HTTP Status Code</label>
                  <select
                    className="form-select"
                    value={redirectStatus}
                    onChange={(e) => setRedirectStatus(Number(e.target.value))}
                  >
                    <option value={301}>301 (Moved Permanently)</option>
                    <option value={302}>302 (Found)</option>
                    <option value={307}>307 (Temporary Redirect)</option>
                    <option value={308}>308 (Permanent Redirect)</option>
                  </select>
                  <p className="form-hint">
                    301/308 for permanent, 302/307 for temporary
                  </p>
                </div>
              </div>
              <div className="form-group">
                <label>Redirect Behavior Options</label>
                <div className="info-box">
                  <p className="info-text">
                    <strong>What do these options do?</strong><br/>
                    These settings control what happens to the URL parts when someone is redirected from your domain.<br/>
                    <a 
                      href="https://github.com/yourusername/aki-cloud/blob/main/docs/REDIRECT_OPTIONS_EXPLAINED.md" 
                      target="_blank" 
                      rel="noopener noreferrer" 
                      style={{color: 'var(--color-accent)', textDecoration: 'underline', fontSize: '12px'}}
                    >
                      📖 View detailed explanation with examples
                    </a>
                  </p>
                </div>
                <div className="checkbox-group">
                  <label className="checkbox-label" title="When enabled, the path from the original URL will be appended to the redirect target. Example: domain.com/page → target.com/page">
                    <input
                      type="checkbox"
                      checked={redirectPreservePath}
                      onChange={(e) => setRedirectPreservePath(e.target.checked)}
                    />
                    <span>Keep URL path after redirect</span>
                    <span className="checkbox-hint">
                      <strong>What it does:</strong> Keeps everything after the domain name<br/>
                      <strong>✓ ON:</strong> oldsite.com<em>/about/team</em> → newsite.com<em>/about/team</em><br/>
                      <strong>✗ OFF:</strong> oldsite.com/about/team → newsite.com (path is removed)
                    </span>
                  </label>
                  <label className="checkbox-label" title="When enabled, the query parameters from the original URL will be passed to the redirect target. Example: domain.com?id=123 → target.com?id=123">
                    <input
                      type="checkbox"
                      checked={redirectPreserveQuery}
                      onChange={(e) => setRedirectPreserveQuery(e.target.checked)}
                    />
                    <span>Keep URL parameters after redirect</span>
                    <span className="checkbox-hint">
                      <strong>What it does:</strong> Keeps tracking codes, IDs, and other URL parameters<br/>
                      <strong>✓ ON:</strong> oldsite.com<em>?utm_source=google&id=123</em> → newsite.com<em>?utm_source=google&id=123</em><br/>
                      <strong>✗ OFF:</strong> oldsite.com?utm_source=google&id=123 → newsite.com (parameters are removed)
                    </span>
                  </label>
                </div>
              </div>
            </div>
          )}
          {mode === 'primary' && (
            <div className="modal-section">
              <p className="form-hint">
                This will convert the domain back to a standard configuration. Existing alias or redirect settings will be removed.
              </p>
            </div>
          )}
          <div className="modal-actions">
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={loading} disabled={mode === 'alias' && availablePrimaries.length === 0}>
              Save Configuration
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

interface RedirectRulesModalProps {
  domain: DomainWithMeta;
  onClose: () => void;
  onSaved: () => void;
}

function RedirectRulesModal({ domain, onClose, onSaved }: RedirectRulesModalProps) {
  const modalRef = useRef<HTMLDivElement>(null);
  const [isMouseDown, setIsMouseDown] = useState(false);
  const [loading, setLoading] = useState(false);

  const forceDomainRedirect = domain.role === 'redirect';
  const initialDomainRule = domain.__meta.domainRule;
  const [domainRedirectEnabled, setDomainRedirectEnabled] = useState(
    forceDomainRedirect || Boolean(initialDomainRule),
  );
  const [domainRuleConfig, setDomainRuleConfig] = useState<DomainRedirectRule>({
    id: initialDomainRule?.id ?? '',
    source: '',
    target: initialDomainRule?.target ?? '',
    status_code: initialDomainRule?.status_code ?? 301,
    preserve_path: initialDomainRule?.preserve_path ?? false,
    preserve_query: initialDomainRule ? initialDomainRule.preserve_query : true,
  });

  const [pathRules, setPathRules] = useState<DomainRedirectRule[]>(
    (domain.__meta.pathRules ?? []).map((rule) => ({ ...rule })),
  );

  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [formRule, setFormRule] = useState<DomainRedirectRule>({
    id: '',
    source: '',
    target: '',
    status_code: 301,
    preserve_path: false,
    preserve_query: true,
  });

  const resetForm = () => {
    setFormRule({ id: '', source: '', target: '', status_code: 301, preserve_path: false, preserve_query: true });
    setEditingIndex(null);
  };

  const handleMouseDown = (event: React.MouseEvent) => {
    if (!modalRef.current?.contains(event.target as Node)) {
      setIsMouseDown(true);
    }
  };

  const handleMouseUp = (event: React.MouseEvent) => {
    if (isMouseDown && !modalRef.current?.contains(event.target as Node)) {
      onClose();
    }
    setIsMouseDown(false);
  };

  const handleEditRule = (index: number) => {
    const rule = pathRules[index];
    setEditingIndex(index);
    setFormRule({ ...rule });
  };

  const handleDeleteRule = (index: number) => {
    const rule = pathRules[index];
    const confirmMessage = `Are you sure you want to remove this path redirect rule?\n\nFrom: ${rule.source}\nTo: ${rule.target}`;
    
    if (!window.confirm(confirmMessage)) {
      return;
    }
    
    setPathRules((prev) => prev.filter((_, i) => i !== index));
    if (editingIndex === index) {
      resetForm();
    }
  };

  const handleRuleSubmit = () => {
    const source = formRule.source.trim();
    const target = formRule.target.trim();
    if (!source.startsWith('/')) {
      toast.error('Source must start with /');
      return;
    }
    if (!target) {
      toast.error('Target is required');
      return;
    }
    const normalized: DomainRedirectRule = {
      ...formRule,
      source,
      target,
    };
    setPathRules((prev) => {
      const next = prev.slice();
      if (editingIndex !== null) {
        next[editingIndex] = normalized;
      } else {
        next.push({ ...normalized, id: normalized.id ?? '' });
      }
      return next;
    });
    resetForm();
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    try {
      if ((forceDomainRedirect || domainRedirectEnabled) && !domainRuleConfig.target.trim()) {
        toast.error('Whole-domain redirect target is required');
        setLoading(false);
        return;
      }
      const rules: DomainRedirectRule[] = [];
      if (forceDomainRedirect || domainRedirectEnabled) {
        rules.push({
          id: domainRuleConfig.id ?? '',
          source: '',
          target: domainRuleConfig.target.trim(),
          status_code: domainRuleConfig.status_code,
          preserve_path: domainRuleConfig.preserve_path,
          preserve_query: domainRuleConfig.preserve_query,
        });
      }
      pathRules.forEach((rule) => {
        rules.push({
          id: rule.id ?? '',
          source: rule.source,
          target: rule.target,
          status_code: rule.status_code,
          preserve_path: rule.preserve_path,
          preserve_query: rule.preserve_query,
        });
      });
      await domainsApi.update(domain.domain, {
        role: forceDomainRedirect ? 'redirect' : domainRedirectEnabled ? 'primary' : domain.role ?? 'primary',
        redirect_rules: rules,
      });
      toast.success('Redirect rules updated');
      onSaved();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to update redirect rules');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onMouseDown={handleMouseDown} onMouseUp={handleMouseUp}>
      <div className="modal" ref={modalRef}>
        <header className="modal-header">
          <h2>Redirect rules for {domain.domain}</h2>
          <button type="button" className="modal-close" onClick={onClose}>
            ×
          </button>
        </header>
        <form className="modal-body" onSubmit={handleSubmit}>
          <section className="modal-section">
            <div className="section-header">
              <h3>Whole-domain redirect</h3>
              {!forceDomainRedirect && (
                <label className="switch-inline">
                  <input
                    type="checkbox"
                    checked={domainRedirectEnabled}
                    onChange={(e) => setDomainRedirectEnabled(e.target.checked)}
                  />
                  Enable
                </label>
              )}
              {forceDomainRedirect && <span className="form-hint">Required for redirect domains</span>}
            </div>
            {(forceDomainRedirect || domainRedirectEnabled) && (
              <div className="form-grid">
                <label>
                  Target
                  <input
                    value={domainRuleConfig.target}
                    onChange={(e) =>
                      setDomainRuleConfig((prev) => ({ ...prev, target: e.target.value }))
                    }
                    placeholder="https://example.com"
                  />
                </label>
                <label>
                  Status code
                  <select
                    value={domainRuleConfig.status_code}
                    onChange={(e) =>
                      setDomainRuleConfig((prev) => ({ ...prev, status_code: Number(e.target.value) }))
                    }
                  >
                    <option value={301}>301</option>
                    <option value={302}>302</option>
                    <option value={307}>307</option>
                    <option value={308}>308</option>
                  </select>
                </label>
                <label className="checkbox-inline" title="Keep the URL path from the original request">
                  <input
                    type="checkbox"
                    checked={domainRuleConfig.preserve_path}
                    onChange={(e) =>
                      setDomainRuleConfig((prev) => ({ ...prev, preserve_path: e.target.checked }))
                    }
                  />
                  <span>Keep path</span>
                  <span className="inline-hint">(/blog/post → target.com/blog/post)</span>
                </label>
                <label className="checkbox-inline" title="Keep URL parameters like ?id=123&utm=google">
                  <input
                    type="checkbox"
                    checked={domainRuleConfig.preserve_query}
                    onChange={(e) =>
                      setDomainRuleConfig((prev) => ({ ...prev, preserve_query: e.target.checked }))
                    }
                  />
                  <span>Keep parameters</span>
                  <span className="inline-hint">(?id=123 → target.com?id=123)</span>
                </label>
              </div>
            )}
          </section>
          <section className="modal-section">
            <div className="section-header">
              <h3>Path redirects</h3>
              {domainRedirectEnabled && (
                <span className="form-hint">Inactive while whole-domain redirect is enabled</span>
              )}
            </div>
            {pathRules.length === 0 ? (
              <p className="form-hint">No path redirects defined</p>
            ) : (
              <ul className="path-rule-list">
                {pathRules.map((rule, index) => (
                  <li key={`${rule.id || rule.source}`} className="path-rule-item">
                    <div className="path-rule-info">
                      <code>{rule.source}</code>
                      <span>→ {rule.target}</span>
                      <span className="path-rule-meta">
                        {rule.status_code}
                        {rule.preserve_path && <span className="path-rule-flag">path</span>}
                        {!rule.preserve_query && <span className="path-rule-flag">no query</span>}
                      </span>
                    </div>
                    <div className="path-rule-actions">
                      <button type="button" onClick={() => handleEditRule(index)}>
                        Edit
                      </button>
                      <button type="button" onClick={() => handleDeleteRule(index)}>
                        Remove
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
            <div className="path-rule-form">
              <div className="form-grid">
                <label>
                  Source
                  <input
                    value={formRule.source}
                    onChange={(e) => setFormRule((prev) => ({ ...prev, source: e.target.value }))}
                    placeholder="/old-path"
                    required
                  />
                </label>
                <label>
                  Target
                  <input
                    value={formRule.target}
                    onChange={(e) => setFormRule((prev) => ({ ...prev, target: e.target.value }))}
                    placeholder="https://example.com/new"
                    required
                  />
                </label>
                <label>
                  Status
                  <select
                    value={formRule.status_code}
                    onChange={(e) => setFormRule((prev) => ({ ...prev, status_code: Number(e.target.value) }))}
                  >
                    <option value={301}>301</option>
                    <option value={302}>302</option>
                    <option value={307}>307</option>
                    <option value={308}>308</option>
                  </select>
                </label>
                <label className="checkbox-inline">
                  <input
                    type="checkbox"
                    checked={formRule.preserve_path}
                    onChange={(e) => setFormRule((prev) => ({ ...prev, preserve_path: e.target.checked }))}
                  />
                  Preserve path
                </label>
                <label className="checkbox-inline">
                  <input
                    type="checkbox"
                    checked={formRule.preserve_query}
                    onChange={(e) => setFormRule((prev) => ({ ...prev, preserve_query: e.target.checked }))}
                  />
                  Preserve query
                </label>
              </div>
              <div className="path-rule-form-actions">
                {editingIndex !== null && (
                  <button type="button" onClick={resetForm}>
                    Cancel edit
                  </button>
                )}
                <button type="button" onClick={handleRuleSubmit}>
                  {editingIndex !== null ? 'Update rule' : 'Add rule'}
                </button>
              </div>
            </div>
          </section>
          <div className="modal-actions">
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={loading}>
              Save Redirect Rules
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
