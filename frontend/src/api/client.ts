import axios from 'axios';
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
  NameServerEntry,
  DomainOverview,
  NameServerStatus,
} from '../types';

const resolveApiBase = (): string => {
  const explicit = import.meta.env.VITE_API_BASE?.trim();
  if (explicit) {
    return explicit.replace(/\/+$/, '');
  }

  if (typeof window !== 'undefined') {
    const current = new URL(window.location.href);
    const configuredPort = import.meta.env.VITE_API_PORT?.trim();

    if (configuredPort) {
      current.port = configuredPort;
    } else if (current.port === '3000') {
      current.port = '8080';
    }

    return `${current.protocol}//${current.host}`.replace(/\/+$/, '');
  }

  return 'http://localhost:8080';
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

export const auth = {
  login: async (credentials: LoginCredentials): Promise<LoginResponse> => {
    const res = await axios.post(`${API_BASE}/auth/login`, credentials);
    return res.data;
  },
};

export const validateSession = async (): Promise<boolean> => {
  try {
    // Try to fetch user domains as a way to validate the session
    await client.get('/domains');
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
    const res = await client.get<Domain[]>('/domains');
    return res.data;
  },
  
  create: async (payload: CreateDomainPayload): Promise<Domain> => {
    const res = await client.post<Domain>('/domains', payload);
    return res.data;
  },
  
  update: async (domain: string, payload: UpdateDomainPayload): Promise<Domain> => {
    const res = await client.put<Domain>(`/domains/${domain}`, payload);
    return res.data;
  },
  
  bulkCreate: async (payload: BulkDomainPayload): Promise<BulkDomainResponse> => {
    const res = await client.post<BulkDomainResponse>('/domains/bulk', payload);
    return res.data;
  },
  
  bulkUpdate: async (payload: BulkUpdateDomainPayload): Promise<BulkDomainResponse> => {
    const res = await client.patch<BulkDomainResponse>('/domains/bulk', payload);
    return res.data;
  },
  
  delete: async (domain: string): Promise<void> => {
    await client.delete(`/domains/${domain}`);
  },
};

export const users = {
  list: async (): Promise<User[]> => {
    const res = await client.get<User[]>('/admin/users');
    return res.data;
  },
  
  create: async (payload: CreateUserPayload): Promise<User> => {
    const res = await client.post<User>('/admin/users', payload);
    return res.data;
  },
  
  update: async (id: string, payload: Partial<CreateUserPayload>): Promise<User> => {
    const res = await client.put<User>(`/admin/users/${id}`, payload);
    return res.data;
  },
  
  delete: async (id: string): Promise<void> => {
    await client.delete(`/admin/users/${id}`);
  },
};

export const nodes = {
  list: async (): Promise<Node[]> => {
    const res = await client.get<Node[]>('/admin/nodes');
    return res.data;
  },
  
  create: async (node: Omit<Node, 'id'>): Promise<Node> => {
    const res = await client.post<Node>('/admin/nodes', node);
    return res.data;
  },
  
  update: async (id: string, node: Node): Promise<Node> => {
    const res = await client.put<Node>(`/admin/nodes/${id}`, node);
    return res.data;
  },
  
  delete: async (id: string): Promise<void> => {
    await client.delete(`/admin/nodes/${id}`);
  },
};

export const infra = {
  nameservers: async (): Promise<NameServerEntry[]> => {
    const res = await client.get<NameServerEntry[]>('/infra/nameservers');
    return res.data;
  },
  
  edges: async (): Promise<string[]> => {
    const res = await client.get<string[]>('/infra/edges');
    return res.data;
  },
  
  checkNameServers: async (targets?: string[]): Promise<NameServerStatus[]> => {
    const payload = targets && targets.length > 0 ? { targets } : {};
    const res = await client.post<NameServerStatus[]>('/admin/infra/nameservers/check', payload);
    return res.data;
  },
  
  rebuild: async (): Promise<void> => {
    await client.post('/admin/ops/rebuild', {});
  },
};

export const admin = {
  domainsOverview: async (): Promise<DomainOverview[]> => {
    const res = await client.get<DomainOverview[]>('/admin/domains/overview');
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
      localStorage.removeItem('auth_token');
      localStorage.removeItem('user');
      
      // Use React Router navigation instead of full page reload
      // This will be handled by the AuthContext
      setTimeout(() => {
        isRedirecting = false;
      }, 1000);
    }
    return Promise.reject(error);
  }
);

export default client;
