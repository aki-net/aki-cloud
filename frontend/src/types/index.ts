export type UserRole = 'admin' | 'user';

export interface User {
  id: string;
  email: string;
  role: UserRole;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export type EncryptionMode = 'off' | 'flexible' | 'full' | 'full_strict' | 'strict_origin_pull';
export type CertificateStatus = 'none' | 'pending' | 'active' | 'errored' | 'awaiting_dns';

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

export interface DomainEdge {
  labels?: string[];
  assignment_salt?: string;
  assigned_ip?: string;
  assigned_node_id?: string;
  assigned_at?: string;
}

export interface ReassignAllEdgesResponse {
  reassigned: number;
  unchanged: number;
  skipped: number;
  failed: number;
  errors?: string[];
}

export interface DomainEdgePayload {
  labels?: string[];
}

export interface Domain {
  domain: string;
  owner: string;
  owner_email?: string;
  origin_ip: string | null;
  proxied: boolean;
  ttl: number;
  updated_at: string;
  tls: DomainTLS;
  edge?: DomainEdge;
}

export interface DomainTLSPayload {
  mode?: EncryptionMode;
  use_recommended?: boolean;
}

export interface CreateDomainPayload {
  domain: string;
  owner?: string;
  origin_ip?: string | null;
  proxied: boolean;
  ttl?: number;
  tls?: DomainTLSPayload;
  edge?: DomainEdgePayload;
}

export interface UpdateDomainPayload {
  origin_ip?: string | null;
  proxied?: boolean;
  ttl?: number;
  owner?: string;
  tls?: DomainTLSPayload;
  edge?: DomainEdgePayload;
}

export interface BulkDomainPayload {
  domains: string[];
  origin_ip?: string | null;
  owner?: string;
  proxied?: boolean;
  ttl?: number;
  tls?: DomainTLSPayload;
  edge?: DomainEdgePayload;
}

export interface BulkUpdateDomainPayload {
  domains: string[];
  origin_ip?: string;
  proxied?: boolean;
  ttl?: number;
  tls?: DomainTLSPayload;
  owner?: string;
  edge?: DomainEdgePayload;
}

export type BulkDomainStatus = 'created' | 'updated' | 'skipped' | 'failed';

export interface BulkDomainResult {
  domain: string;
  status: BulkDomainStatus;
  error?: string;
  record?: Domain;
}

export interface BulkDomainResponse {
  results: BulkDomainResult[];
  success: number;
  failed: number;
  skipped: number;
}

export interface CreateUserPayload {
  email: string;
  password: string;
  role: UserRole;
}

export type NodeRole = 'edge' | 'nameserver';

export interface Node {
  id: string;
  name: string;
  ips: string[];
  ns_ips: string[];
  ns_label?: string;
  ns_base_domain?: string;
  edge_ips?: string[];
  api_endpoint?: string;
  roles?: NodeRole[];
  labels?: string[];
  status?: 'idle' | 'pending' | 'healthy' | 'degraded' | 'offline';
  status_message?: string;
  healthy_edges?: number;
  total_edges?: number;
  last_health_at?: string;
  last_seen_at?: string;
}

export interface EdgeEndpoint {
  node_id: string;
  node_name: string;
  ip: string;
  labels?: string[];
  roles?: NodeRole[];
}

export interface NameServerEntry {
  node_id: string;
  name: string;
  fqdn: string;
  ipv4: string;
}

export interface ExtensionAction {
  key: string;
  label: string;
  description?: string;
}

export interface Extension {
  key: string;
  name: string;
  description: string;
  category: string;
  scope: string;
  enabled: boolean;
  config?: Record<string, unknown>;
  actions?: ExtensionAction[];
  updated_at?: string;
  updated_by?: string;
}

export interface DomainOverview {
  domain: string;
  owner_id: string;
  owner_email?: string;
  owner_exists: boolean;
  origin_ip: string;
  proxied: boolean;
  ttl: number;
  updated_at: string;
  tls_mode?: EncryptionMode;
  tls_status?: CertificateStatus;
  tls_use_recommended?: boolean;
  tls_recommended_mode?: EncryptionMode;
  tls_expires_at?: string;
  tls_last_error?: string;
  tls_retry_after?: string;
  edge_ip?: string;
  edge_node_id?: string;
  edge_labels?: string[];
  edge_assigned_at?: string;
}

export interface NameServerStatus {
  node_id: string;
  name: string;
  fqdn: string;
  ipv4: string;
  healthy: boolean;
  latency_ms: number;
  message?: string;
  checked_at?: string;
}

export interface AnalyticsData {
  totalDomains: number;
  activeDomains: number;
  totalUsers: number;
  activeNodes: number;
  tlsEnabled: number;
  proxiedDomains: number;
  domainsOverTime: Array<{ date: string; count: number }>;
  tlsStatusDistribution: Array<{ status: string; count: number; percentage: number }>;
  nodeHealth: Array<{ node: string; status: 'healthy' | 'degraded' | 'down'; latency: number }>;
  recentActivity: Array<{ timestamp: string; action: string; details: string }>;
}
