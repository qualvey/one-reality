export type MatchLevel = 'same_asn' | 'same_country' | 'global';

export interface TargetItem {
  source?: string;
  domain: string;
  ip: string;
  asn: string;
  country: string;
  stars: number;
  handshake_ms: number;
  cert_days: number;
  status_code: number;
  page_title?: string;
  is_cdn: boolean;
  is_default_page: boolean;
  default_page_type?: string;
  created_at: string;
}

export interface RankedTargetItem extends TargetItem {
  match_level: MatchLevel;
  score: number;
}

export interface TargetSummaryInfo {
  target_ip: string;
  asn: string;
  country: string;
  cidr_count?: number;
  total_ips?: number;
  has_checkpoint?: boolean;
  last_checkpoint_ip?: string;
  completed_cidr_count?: number;
  same_asn_hits: number;
  total_hits: number;
}

export interface TargetRecord {
  domain: string;
  asn: string;
  country: string;
  ip: string;
  port: number;
  handshake_ms: number;
  cert_days: number;
  status_code: number;
  page_title?: string;
  is_cdn: boolean;
  is_hot: boolean;
  is_default_page: boolean;
  default_page_type?: string;
  stars: number;
  is_active: boolean;
  check_fail_count: number;
  first_seen_at: string;
  last_checked_at: string;
}

export interface TargetStats {
  total_targets: number;
  active_targets: number;
  five_star_targets: number;
  total_asns: number;
  avg_handshake_ms: number;
  country_counts: Record<string, number>;
  star_counts: Record<string, number>;
}

export interface ASNRecord {
  asn: number;
  name: string;
  country: string;
  total_ips: number;
  priority: number;
  scan_status: string;
  last_scanned_at?: string;
  success_target_count: number;
  updated_at: string;
}
