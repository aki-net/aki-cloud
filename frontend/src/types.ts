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

export type EncryptionMode = 'off' | 'flexible' | 'full' | 'full_strict' | 'strict_origin_pull';
export type CertificateStatus = 'none' | 'pending' | 'active' | 'errored';

export interface DomainTLSCertificate {
  cert_chain_pem?: string;
  issuer?: string;
  not_before?: string;
  not_after?: string;
  serial_number?: string;
  cert_url?: string;
  cert_stable_url?: string;
}

export interface OriginPullMaterial {
  certificate_pem?: string;
  ca_pem?: string;
  not_before?: string;
  not_after?: string;
  fingerprint?: string;
}

export interface DomainTLS {
  mode: EncryptionMode;
  use_recommended: boolean;
  recommended_mode?: EncryptionMode;
  recommended_at?: string;
  status: CertificateStatus;
  last_error?: string;
  retry_after?: string;
  certificate?: DomainTLSCertificate;
  origin_pull_secret?: OriginPullMaterial;
}

export interface DomainRecord {
  domain: string;
  owner: string;
  origin_ip: string;
  proxied: boolean;
  ttl: number;
  updated_at: string;
  tls: DomainTLS;
}

export interface DomainTLSPayload {
  mode?: EncryptionMode;
  use_recommended?: boolean;
}

export interface CreateDomainPayload {
  domain: string;
  owner?: string;
  origin_ip: string;
  proxied: boolean;
  ttl?: number;
  tls?: DomainTLSPayload;
}

export interface UpsertDomainPayload {
  origin_ip: string;
  proxied: boolean;
  ttl?: number;
  owner?: string;
  tls?: DomainTLSPayload;
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

export interface DomainOverview {
  domain: string;
  owner_id: string;
  owner_email?: string;
  owner_exists: boolean;
  origin_ip: string;
  proxied: boolean;
  updated_at: string;
  tls_mode?: EncryptionMode;
  tls_status?: CertificateStatus;
  tls_use_recommended?: boolean;
  tls_recommended_mode?: EncryptionMode;
  tls_expires_at?: string;
  tls_last_error?: string;
}

export interface NameServerStatus {
  node_id: string;
  name: string;
  fqdn: string;
  ipv4: string;
  healthy: boolean;
  latency_ms: number;
  message?: string;
}
