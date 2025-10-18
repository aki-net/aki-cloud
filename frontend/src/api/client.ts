import axios from "axios";
import {
  LoginCredentials,
  User,
  Domain,
  CreateDomainPayload,
  UpdateDomainPayload,
  BulkDomainPayload,
  BulkDomainResponse,
  BulkUpdateDomainPayload,
  CreateUserPayload,
  Node,
  EdgeEndpoint,
  NameServerEntry,
  DomainOverview,
  NameServerStatus,
  ReassignAllEdgesResponse,
  Extension,
  DomainWhoisOverridePayload,
  SearchBotDomainStats,
  SearchBotNodeUsage,
  WAFDefinition,
  DomainDNSRecord,
  CreateDNSRecordPayload,
  UpdateDNSRecordPayload,
  BackupStatus,
  BackupDescriptor,
  BackupRunResult,
  BackupRestoreResult,
} from "../types";

const resolveApiBase = (): string => {
  const explicit = import.meta.env.VITE_API_BASE?.trim();
  if (explicit) {
    return explicit.replace(/\/+$/, "");
  }

  if (typeof window !== "undefined") {
    const current = new URL(window.location.href);
    const configuredPort = import.meta.env.VITE_API_PORT?.trim();

    if (configuredPort) {
      current.port = configuredPort;
    } else if (current.port === "3000") {
      current.port = "8080";
    }

    return `${current.protocol}//${current.host}`.replace(/\/+$/, "");
  }

  return "http://localhost:8080";
};

const API_BASE = resolveApiBase();

const client = axios.create({
  baseURL: `${API_BASE}/api/v1`,
  timeout: 10_000,
});

export const setAuthToken = (token: string | null) => {
  if (token) {
    client.defaults.headers.common.Authorization = `Bearer ${token}`;
  } else {
    delete client.defaults.headers.common.Authorization;
  }
};

interface LoginResponse {
  token: string;
  user: User;
  role: string;
}

interface NodePayload {
  name: string;
  ips: string[];
  ns_ips?: string[];
  edge_ips?: string[];
  labels?: string[];
  ns_label?: string;
  ns_base_domain?: string;
  api_endpoint?: string;
}

export const auth = {
  login: async (credentials: LoginCredentials): Promise<LoginResponse> => {
    const res = await axios.post(`${API_BASE}/auth/login`, credentials);
    return res.data;
  },
};

export const validateSession = async (): Promise<boolean> => {
  try {
    // Try to fetch user domains as a way to validate the session
    await client.get("/domains");
    return true;
  } catch (error: any) {
    if (error.response?.status === 401) {
      return false;
    }
    // For other errors, assume session is still valid
    return true;
  }
};

export const domains = {
  list: async (): Promise<Domain[]> => {
    const res = await client.get<Domain[]>("/domains");
    return res.data;
  },

  create: async (payload: CreateDomainPayload): Promise<Domain> => {
    const res = await client.post<Domain>("/domains", payload);
    return res.data;
  },

  update: async (
    domain: string,
    payload: UpdateDomainPayload,
  ): Promise<Domain> => {
    const res = await client.put<Domain>(`/domains/${domain}`, payload);
    return res.data;
  },

  purgeCache: async (domain: string): Promise<Domain> => {
    const res = await client.post<Domain>(`/domains/${domain}/cache/purge`, {});
    return res.data;
  },

  refreshWhois: async (domain: string): Promise<Domain> => {
    const res = await client.post<Domain>(`/domains/${domain}/whois/refresh`, {});
    return res.data;
  },

  overrideWhois: async (
    domain: string,
    payload: DomainWhoisOverridePayload,
  ): Promise<Domain> => {
    const res = await client.put<Domain>(`/domains/${domain}/whois`, payload);
    return res.data;
  },

  reassignEdge: async (domain: string): Promise<Domain> => {
    const res = await client.post<Domain>(
      `/domains/${domain}/edge/reassign`,
      {},
    );
    return res.data;
  },

  reassignAllEdges: async (): Promise<ReassignAllEdgesResponse> => {
    const res = await client.post<ReassignAllEdgesResponse>(
      "/domains/edge/reassign-all",
      {},
    );
    return res.data;
  },

  bulkCreate: async (
    payload: BulkDomainPayload,
  ): Promise<BulkDomainResponse> => {
    const res = await client.post<BulkDomainResponse>("/domains/bulk", payload);
    return res.data;
  },

  bulkUpdate: async (
    payload: BulkUpdateDomainPayload,
  ): Promise<BulkDomainResponse> => {
    const res = await client.patch<BulkDomainResponse>(
      "/domains/bulk",
      payload,
    );
    return res.data;
  },

  delete: async (domain: string): Promise<void> => {
    await client.delete(`/domains/${domain}`);
  },

  dnsRecords: {
    list: async (domain: string): Promise<DomainDNSRecord[]> => {
      const res = await client.get<DomainDNSRecord[]>(
        `/domains/${encodeURIComponent(domain)}/dns-records`,
      );
      return res.data;
    },
    create: async (
      domain: string,
      payload: CreateDNSRecordPayload,
    ): Promise<DomainDNSRecord> => {
      const res = await client.post<DomainDNSRecord>(
        `/domains/${encodeURIComponent(domain)}/dns-records`,
        payload,
      );
      return res.data;
    },
    update: async (
      domain: string,
      id: string,
      payload: UpdateDNSRecordPayload,
    ): Promise<DomainDNSRecord> => {
      const res = await client.put<DomainDNSRecord>(
        `/domains/${encodeURIComponent(domain)}/dns-records/${encodeURIComponent(id)}`,
        payload,
      );
      return res.data;
    },
    delete: async (domain: string, id: string): Promise<void> => {
      await client.delete(
        `/domains/${encodeURIComponent(domain)}/dns-records/${encodeURIComponent(id)}`,
      );
    },
  },

  searchbots: {
    stats: async (
      domain: string,
      refresh = false,
    ): Promise<SearchBotDomainStats> => {
      const base = `/domains/${encodeURIComponent(domain)}/searchbots/stats`;
      const path = refresh ? `${base}?refresh=1` : base;
      const res = await client.get<SearchBotDomainStats>(path);
      return res.data;
    },

    export: async (domain: string, bot: string): Promise<Blob> => {
      const path = `/domains/${encodeURIComponent(domain)}/searchbots/logs/${encodeURIComponent(bot)}`;
      const res = await client.get(path, { responseType: "blob" });
      return res.data as Blob;
    },
  },
};

export const waf = {
  definitions: async (): Promise<WAFDefinition[]> => {
    const res = await client.get<WAFDefinition[]>("/waf/definitions");
    return res.data;
  },
};

export const users = {
  list: async (): Promise<User[]> => {
    const res = await client.get<User[]>("/admin/users");
    return res.data;
  },

  create: async (payload: CreateUserPayload): Promise<User> => {
    const res = await client.post<User>("/admin/users", payload);
    return res.data;
  },

  update: async (
    id: string,
    payload: Partial<CreateUserPayload>,
  ): Promise<User> => {
    const res = await client.put<User>(`/admin/users/${id}`, payload);
    return res.data;
  },

  delete: async (id: string): Promise<void> => {
    await client.delete(`/admin/users/${id}`);
  },
};

export const nodes = {
  list: async (): Promise<Node[]> => {
    const res = await client.get<Node[]>("/admin/nodes");
    return res.data;
  },

  create: async (node: NodePayload): Promise<Node> => {
    const res = await client.post<Node>("/admin/nodes", node);
    return res.data;
  },

  update: async (id: string, node: Partial<NodePayload>): Promise<Node> => {
    const res = await client.put<Node>(`/admin/nodes/${id}`, node);
    return res.data;
  },

  delete: async (id: string): Promise<void> => {
    await client.delete(`/admin/nodes/${id}`);
  },
};

export const extensionsApi = {
  list: async (): Promise<Extension[]> => {
    const res = await client.get<Extension[]>("/admin/extensions");
    return res.data;
  },

  update: async (
    key: string,
    payload: { enabled?: boolean; config?: Record<string, unknown> },
  ): Promise<Extension> => {
    const res = await client.put<Extension>(`/admin/extensions/${key}`, payload);
    return res.data;
  },

  action: async (
    key: string,
    action: string,
  ): Promise<{ status: string }> => {
    const res = await client.post<{ status: string }>(
      `/admin/extensions/${key}/actions/${action}`,
      {},
    );
    return res.data;
  },

  searchBotUsage: async (): Promise<SearchBotNodeUsage[]> => {
    const res = await client.get<SearchBotNodeUsage[]>(
      "/admin/searchbots/usage",
    );
    return res.data;
  },
};

export const backups = {
  status: async (): Promise<BackupStatus> => {
    const res = await client.get("/admin/backups/status");
    const data = res.data as any;
    return {
      enabled: Boolean(data?.enabled),
      hasCredentials: Boolean(data?.has_credentials),
      running: Boolean(data?.running),
      lastRunStartedAt: data?.last_run_started_at || undefined,
      lastRunCompletedAt: data?.last_run_completed_at || undefined,
      lastResult: data?.last_result || undefined,
      lastError: data?.last_error || undefined,
      lastBackupName: data?.last_backup_name || undefined,
      nextRunAt: data?.next_run_at || undefined,
      frequency: data?.frequency ?? "",
      include: Array.isArray(data?.include)
        ? (data.include as unknown[])
            .map((item) => (typeof item === "string" ? item : String(item)))
        : [],
    };
  },

  list: async (): Promise<BackupDescriptor[]> => {
    const res = await client.get<any[]>("/admin/backups");
    return (res.data || []).map((item) => ({
      name: item?.name ?? "",
      sizeBytes: Number(item?.size_bytes ?? 0),
      createdAt: item?.created_at ?? "",
      includes: Array.isArray(item?.includes)
        ? (item.includes as unknown[]).map((entry) =>
            typeof entry === "string" ? entry : String(entry),
          )
        : undefined,
    }));
  },

  run: async (payload: {
    include?: string[];
    force?: boolean;
    reason?: string;
  }): Promise<BackupRunResult> => {
    const res = await client.post<any>("/admin/backups/run", payload ?? {});
    const data = res.data ?? {};
    return {
      name: data.name ?? "",
      uploaded: Boolean(data.uploaded),
      includes: Array.isArray(data.includes)
        ? (data.includes as unknown[]).map((entry) =>
            typeof entry === "string" ? entry : String(entry),
          )
        : [],
      sizeBytes: Number(data.size_bytes ?? 0),
      startedAt: data.started_at || undefined,
      completedAt: data.completed_at || undefined,
    };
  },

  restore: async (payload: {
    name: string;
    include?: string[];
    wipe?: {
      domains?: boolean;
      users?: boolean;
      extensions?: boolean;
      nodes?: boolean;
      edge_health?: boolean;
    };
  }): Promise<BackupRestoreResult> => {
    const res = await client.post<any>("/admin/backups/restore", payload);
    const data = res.data ?? {};
    return {
      name: data.name ?? payload.name,
      includes: Array.isArray(data.includes)
        ? (data.includes as unknown[]).map((entry) =>
            typeof entry === "string" ? entry : String(entry),
          )
        : [],
      domains: Number(data.domains ?? 0),
      users: Number(data.users ?? 0),
      extensions: Boolean(data.extensions),
      nodes: Number(data.nodes ?? 0),
      edgeHealth: Number(data.edge_health ?? 0),
      startedAt: data.started_at ?? "",
      completedAt: data.completed_at ?? "",
    };
  },

  uploadFile: async (file: File, name?: string): Promise<BackupRunResult> => {
    const formData = new FormData();
    formData.append("file", file);
    if (name && name.trim() !== "") {
      formData.append("name", name.trim());
    }
    const res = await client.post<any>('/admin/backups/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    const data = res.data ?? {};
    return {
      name: data.name ?? data.backupName ?? "",
      uploaded: true,
      includes: Array.isArray(data.includes)
        ? (data.includes as unknown[]).map((entry) =>
            typeof entry === "string" ? entry : String(entry),
          )
        : [],
      sizeBytes: Number(data.size_bytes ?? 0),
      startedAt: data.started_at || undefined,
      completedAt: data.completed_at || undefined,
    };
  },

  restoreFromFile: async (options: {
    file: File;
    include?: string[];
    wipe?: {
      domains?: boolean;
      users?: boolean;
      extensions?: boolean;
      nodes?: boolean;
      edge_health?: boolean;
    };
  }): Promise<BackupRestoreResult> => {
    const formData = new FormData();
    formData.append('file', options.file);
    if (options.include) {
      options.include.forEach((value) => formData.append('include', value));
    }
    if (options.wipe?.domains !== undefined) {
      formData.append('wipe_domains', String(options.wipe.domains));
    }
    if (options.wipe?.users !== undefined) {
      formData.append('wipe_users', String(options.wipe.users));
    }
    if (options.wipe?.extensions !== undefined) {
      formData.append('wipe_extensions', String(options.wipe.extensions));
    }
    if (options.wipe?.nodes !== undefined) {
      formData.append('wipe_nodes', String(options.wipe.nodes));
    }
    if (options.wipe?.edge_health !== undefined) {
      formData.append('wipe_edge', String(options.wipe.edge_health));
    }
    const res = await client.post<any>('/admin/backups/restore/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    const data = res.data ?? {};
    return {
      name: data.name ?? "",
      includes: Array.isArray(data.includes)
        ? (data.includes as unknown[]).map((entry) =>
            typeof entry === "string" ? entry : String(entry),
          )
        : [],
      domains: Number(data.domains ?? 0),
      users: Number(data.users ?? 0),
      extensions: Boolean(data.extensions),
      nodes: Number(data.nodes ?? 0),
      edgeHealth: Number(data.edge_health ?? 0),
      startedAt: data.started_at ?? "",
      completedAt: data.completed_at ?? "",
    };
  },
};

export const infra = {
  nameservers: async (): Promise<NameServerEntry[]> => {
    const res = await client.get<NameServerEntry[]>("/infra/nameservers");
    return res.data;
  },

  edges: async (): Promise<EdgeEndpoint[]> => {
    const res = await client.get<EdgeEndpoint[]>("/infra/edges");
    return res.data;
  },
  nameserverStatus: async (): Promise<NameServerStatus[]> => {
    const res = await client.get<NameServerStatus[]>(
      "/admin/infra/nameservers/status",
    );
    return res.data;
  },

  checkNameServers: async (targets?: string[]): Promise<NameServerStatus[]> => {
    const payload = targets && targets.length > 0 ? { targets } : {};
    const res = await client.post<NameServerStatus[]>(
      "/admin/infra/nameservers/check",
      payload,
    );
    return res.data;
  },

  joinCommand: async (): Promise<string> => {
    const res = await client.get<{ command: string }>(
      "/admin/nodes/join-command",
    );
    return res.data.command;
  },

  rebuild: async (): Promise<void> => {
    await client.post("/admin/ops/rebuild", {});
  },
};

export const admin = {
  domainsOverview: async (): Promise<DomainOverview[]> => {
    const res = await client.get<DomainOverview[]>("/admin/domains/overview");
    return res.data;
  },
};

// Interceptor for automatic logout on 401
let isRedirecting = false;
client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && !isRedirecting) {
      // Prevent multiple redirects
      isRedirecting = true;

      // Clear auth data
      setAuthToken(null);
      localStorage.removeItem("auth_token");
      localStorage.removeItem("user");

      // Use React Router navigation instead of full page reload
      // This will be handled by the AuthContext
      setTimeout(() => {
        isRedirecting = false;
      }, 1000);
    }
    return Promise.reject(error);
  },
);

export default client;
