export type UserRole = 'admin' | 'user';

export interface SessionUser {
  id: string;
  email: string;
  role: UserRole;
}

export interface AuthContextValue {
  token: string | null;
  user: SessionUser | null;
  isAuthenticated: boolean;
  login: (payload: LoginPayload) => Promise<SessionUser>;
  logout: () => void;
}

export interface LoginPayload {
  email: string;
  password: string;
}

export interface DomainRecord {
  domain: string;
  owner: string;
  origin_ip: string;
  proxied: boolean;
  ttl: number;
  updated_at: string;
}

export interface CreateDomainPayload {
  domain: string;
  owner?: string;
  origin_ip: string;
  proxied: boolean;
  ttl?: number;
}

export interface UpsertDomainPayload {
  origin_ip: string;
  proxied: boolean;
  ttl?: number;
  owner?: string;
}

export interface UserRecord {
  id: string;
  email: string;
  role: UserRole;
}

export interface CreateUserPayload {
  email: string;
  password: string;
  role: UserRole;
}

export interface NodeRecord {
  id: string;
  name: string;
  ips: string[];
  ns_ips: string[];
  ns_label?: string;
  ns_base_domain?: string;
  edge_ips?: string[];
  api_endpoint?: string;
}

export interface NameServerEntry {
  node_id: string;
  name: string;
  fqdn: string;
  ipv4: string;
}
