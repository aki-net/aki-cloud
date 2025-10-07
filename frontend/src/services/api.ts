import axios from 'axios';
import {
  CreateDomainPayload,
  CreateUserPayload,
  DomainRecord,
  LoginPayload,
  NameServerEntry,
  NodeRecord,
  SessionUser,
  UpsertDomainPayload,
  UserRecord,
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

export const setToken = (token: string | null) => {
  if (token) {
    client.defaults.headers.common.Authorization = `Bearer ${token}`;
  } else {
    delete client.defaults.headers.common.Authorization;
  }
};

interface LoginResponse {
  token: string;
  user: SessionUser;
  role: string;
}

export const loginRequest = async (payload: LoginPayload): Promise<LoginResponse> => {
  const res = await axios.post(`${API_BASE}/auth/login`, payload);
  return res.data as LoginResponse;
};

export const fetchDomains = async (): Promise<DomainRecord[]> => {
  const res = await client.get<DomainRecord[]>('/domains');
  return res.data;
};

export const createDomain = async (payload: CreateDomainPayload): Promise<DomainRecord> => {
  const res = await client.post<DomainRecord>('/domains', payload);
  return res.data;
};

export const updateDomain = async (domain: string, payload: UpsertDomainPayload): Promise<DomainRecord> => {
  const res = await client.put<DomainRecord>(`/domains/${domain}`, payload);
  return res.data;
};

export const deleteDomain = async (domain: string) => {
  await client.delete(`/domains/${domain}`);
};

export const fetchUsers = async (): Promise<UserRecord[]> => {
  const res = await client.get<UserRecord[]>('/admin/users');
  return res.data;
};

export const createUser = async (payload: CreateUserPayload) => {
  const res = await client.post<UserRecord>('/admin/users', payload);
  return res.data;
};

export const updateUser = async (id: string, payload: Partial<CreateUserPayload>) => {
  const res = await client.put<UserRecord>(`/admin/users/${id}`, payload);
  return res.data;
};

export const deleteUser = async (id: string) => {
  await client.delete(`/admin/users/${id}`);
};

export const fetchNodes = async (): Promise<NodeRecord[]> => {
  const res = await client.get<NodeRecord[]>('/admin/nodes');
  return res.data;
};

export const upsertNode = async (node: NodeRecord) => {
  if (node.id) {
    const res = await client.put<NodeRecord>(`/admin/nodes/${node.id}`, node);
    return res.data;
  }
  const res = await client.post<NodeRecord>('/admin/nodes', node);
  return res.data;
};

export const deleteNode = async (id: string) => {
  await client.delete(`/admin/nodes/${id}`);
};

export const fetchNameServers = async (): Promise<NameServerEntry[]> => {
  const res = await client.get<NameServerEntry[]>('/infra/nameservers');
  return res.data;
};

export const fetchEdges = async (): Promise<string[]> => {
  const res = await client.get<string[]>('/infra/edges');
  return res.data;
};

export const rebuildServices = async () => {
  await client.post('/admin/ops/rebuild', {});
};

client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      setToken(null);
    }
    return Promise.reject(error);
  },
);

export default client;
