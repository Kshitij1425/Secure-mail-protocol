/**
 * API types. These mirror backend/securemailscope/api/schemas.py exactly.
 * All string values originate from untrusted captures and are rendered as text only.
 */

export type AnalysisStatus = 'pending' | 'processing' | 'completed' | 'failed';
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface CaptureSummary {
  capture_id: string;
  filename: string;
  file_hash: string;
  upload_timestamp: string | null;
  analysis_status: AnalysisStatus;
  analysis_error: string | null;
  packet_count: number;
  stream_count: number;
  email_session_count: number;
  tls_session_count: number;
  posture_score: number | null;
  posture_status: string | null;
  policy_profile: string | null;
  capture_start: string | null;
  analysis_timestamp: string | null;
  findings_count: number;
  anomalies_count: number;
  severity_counts: Record<string, number>;
}

export interface CaptureDetail extends CaptureSummary {
  file_size: number;
  file_format: string | null;
  analysis_duration_seconds: number | null;
  capture_end: string | null;
  scoring_policy_version: string | null;
  rule_policy_version: string | null;
  ml_engine_version: string | null;
  ml_status: string | null;
  ml_anomalies_detected: number;
  sessions_count: number;
  certificates_count: number;
  reports_count: number;
  coverage: Record<string, number>;
  ingestion: Record<string, unknown>;
}

export interface SessionSummary {
  session_id: string;
  capture_id: string;
  stream_id: string;
  protocol: string;
  source_ip: string | null;
  source_port: number | null;
  dest_ip: string | null;
  dest_port: number | null;
  start_timestamp: string | null;
  end_timestamp: string | null;
  packet_count: number;
  byte_count: number;
  detection_method: string | null;
  implicit_tls: boolean;
  starttls_state: string | null;
  tls_version: string | null;
  cipher_suite: string | null;
  has_forward_secrecy: boolean | null;
  handshake_status: string | null;
  certificate_visibility: string | null;
  reconstruction_quality: string | null;
  has_findings: boolean;
  has_anomaly: boolean;
  anomaly_level: string | null;
}

export interface SessionDetail extends SessionSummary {
  key_exchange: string | null;
  key_exchange_group: string | null;
  sni: string | null;
  client_hello_version: string | null;
  starttls_advertised: boolean | null;
  handshake_complete: boolean;
  anomaly_score: number | null;
  first_frame: number | null;
  last_frame: number | null;
  findings: string[];
  certificates: string[];
  anomaly_id: number | null;
  detail: {
    reconstruction?: Record<string, unknown>;
    starttls?: { plaintext_auth_mechanisms?: string[]; server_response?: string | null; attempts?: number };
    tls?: { alerts?: { description?: string; level?: string; encrypted?: boolean }[]; alpn?: string[];
            cipher_strength?: string | null; client_max_version?: string | null } | null;
    chain?: { status?: string };
    evidence_frames?: Record<string, number>;
  };
}

export interface FindingSummary {
  finding_id: string;
  capture_id: string;
  rule_id: string;
  title: string;
  severity: SeverityLevel;
  category: string;
  dimension: string | null;
  evidence_type: string | null;
  session_id: string | null;
  confidence: number;
  risk_contribution: number;
  priority: number | null;
  status: string;
}

export interface FindingDetail extends FindingSummary {
  explanation: string | null;
  recommendation: string | null;
  references: string | null;
  evidence: Record<string, unknown>;
  evidence_frames: number[];
  timestamp: string | null;
  affected_sessions: string[];
  why_it_matters: string | null;
  expected_effect: string | null;
}

export interface CertificateSummary {
  certificate_id: string;
  capture_id: string;
  session_id: string;
  chain_position: number;
  fingerprint_sha256: string;
  subject: string | null;
  issuer: string | null;
  common_name: string | null;
  not_after: string | null;
  is_expired: boolean;
  is_not_yet_valid: boolean;
  is_self_signed: boolean;
  public_key_algorithm: string | null;
  public_key_size_bits: number | null;
  trust_status: string;
}

export interface CertificateDetail extends CertificateSummary {
  serial_number: string | null;
  not_before: string | null;
  validity_reference: string | null;
  is_ca: boolean | null;
  signature_algorithm: string | null;
  san_list: string[];
  weak_key: boolean;
  weak_signature: boolean;
  issued_by_next: string | null;
  seen_in_sessions: string[];
}

export interface AnomalySummary {
  id: number;
  capture_id: string;
  session_id: string;
  is_anomaly: boolean;
  anomaly_score: number | null;
  anomaly_level: string | null;
  model_version: string | null;
}

export interface AnomalyDetail extends AnomalySummary {
  explanation: string | null;
  features: Record<string, number | string | boolean | null>;
  timestamp: string | null;
  classification: string;
}

export interface Contributor {
  root_issue: string;
  severity: string;
  affected_sessions: number;
  total_sessions?: number | null;
  prevalence: number;
  impact_points: number;
  explanation: string;
  finding_ids: string[];
}

export interface DimensionScore {
  dimension: string;
  name: string;
  score: number | null;
  weight: number;
  affected_sessions: number;
  assessable_sessions: number;
  findings_count: number;
  coverage_percent: number;
  evidence_quality: string;
  top_contributors: Contributor[];
}

export interface RemediationItem {
  priority: number;
  rule_id: string;
  title: string;
  severity: SeverityLevel;
  affected_sessions: number;
  finding_count: number;
  recommendation: string;
  references: string;
  why_it_matters: string | null;
  expected_effect: string | null;
  session_ids: string[];
  finding_ids: string[];
}

export interface PostureResponse {
  capture_id: string;
  overall_score: number | null;
  status: string;
  scoring_policy_version: string;
  analysis_timestamp: string | null;
  total_sessions: number;
  tls_sessions: number;
  sessions_with_findings: number;
  findings_count: number;
  tls_coverage_percent: number;
  certificate_coverage_percent: number;
  coverage_percent: number;
  dimension_scores: DimensionScore[];
  top_contributors: Contributor[];
  root_cause_groups: { root_issue: string; severity: string; affected_sessions: number; finding_count: number }[];
  remediation_plan: RemediationItem[];
}

export interface ReportSummary {
  report_id: string;
  capture_id: string;
  report_type: 'json' | 'html' | 'pdf';
  file_size: number;
  sha256: string | null;
  redacted: boolean;
  created_at: string | null;
}

export interface AnalysisResponse {
  capture_id: string;
  status: AnalysisStatus;
  message: string;
}

export interface PolicyProfile {
  id: string;
  name: string;
  description: string;
  min_rsa_bits: number;
  min_ec_bits: number;
  min_dh_bits: number;
  deprecated_version_severity: Record<string, string>;
  severity_overrides: Record<string, string>;
  disabled_rules: string[];
  enabled_optional_rules: string[];
  rationale: Record<string, string>;
}

export type EvidenceClass = 'OBSERVED' | 'INFERRED' | 'POTENTIAL_INDICATOR' | 'INSUFFICIENT_EVIDENCE'
  | 'NOT_OBSERVABLE' | 'ML_ANOMALY' | 'ML_ASSESSMENT' | string;

export interface TimelineEvent {
  ts: string | null;
  frame: number | null;
  session_id: string;
  phase: 'capture' | 'analysis';
  type: string;
  label: string;
  evidence_class: EvidenceClass;
  finding_id?: string;
  severity?: SeverityLevel;
}

export interface CertificateInventoryItem {
  fingerprint_sha256: string;
  subject: string | null;
  issuer: string | null;
  common_name: string | null;
  serial_number: string | null;
  not_before: string | null;
  not_after: string | null;
  public_key_algorithm: string | null;
  public_key_size_bits: number | null;
  signature_algorithm: string | null;
  san_list: string[];
  is_ca: boolean | null;
  is_self_signed: boolean;
  is_expired: boolean;
  is_not_yet_valid: boolean;
  weak_key: boolean;
  weak_signature: boolean;
  trust_status: string;
  days_to_expiry_at_capture: number | null;
  certificate_ids: string[];
  session_ids: string[];
  servers: string[];
  sni_requested: string[];
  chain_positions: number[];
  extraction: string;
  chain_linkage: string[];
  trust_validation: string;
  session_count: number;
}

export interface ChainLink { status: string; reason?: string; [key: string]: unknown }

export interface EvidenceChain {
  capture_id: string;
  status: string;
  policy_profile: string;
  finding: { finding_id: string; rule_id: string; title: string; severity: SeverityLevel; confidence: number;
             evidence_type: EvidenceClass; dimension: string | null; description: string; risk_contribution: number };
  session: null | { session_id: string; protocol: string; implicit_tls: boolean; client: { ip: string; port: number };
                    server: { ip: string; port: number }; start_time: string | null; starttls_state: string;
                    detection: { method: string | null; confidence: number | null } };
  tcp_stream: null | { stream_id: string; first_frame: number; last_frame: number; quality: string };
  tls: ChainLink & { negotiated_version?: string | null; cipher_suite?: string | null; key_exchange?: string | null;
                     key_exchange_group?: string | null; forward_secrecy?: boolean | null; sni?: string | null;
                     handshake_status?: string | null; certificate_visibility?: string | null };
  certificate: ChainLink & { certificate_id?: string; subject?: string; issuer?: string; serial_number?: string;
                             fingerprint_sha256?: string; not_before?: string; not_after?: string; is_expired?: boolean;
                             chain_position?: number; trust?: string };
  evidence: { class: EvidenceClass; values: Record<string, unknown>; frames: number[]; events: TimelineEvent[] };
  recommendation: { action: string; why_it_matters: string | null; expected_effect: string | null; references: string };
}

export interface CompareSide {
  capture_id: string; filename: string; sha256: string; captured_at: string | null; analyzed_at: string | null;
  policy_profile: string; score: number | null; status: string; email_sessions: number; tls_sessions: number;
  findings: number; anomalies: number;
}

export interface CompareFinding {
  rule_id: string; title: string; asset: string; severity_a: SeverityLevel | null; severity_b: SeverityLevel | null;
  sessions_a: number; sessions_b: number; finding_ids_a: string[]; finding_ids_b: string[];
}

export interface Changed<T> { a: T; b: T; changed: boolean }

export interface CompareAsset {
  asset: string; present_in: 'both' | 'a' | 'b';
  tls_versions: Changed<string[]>; cipher_suites: Changed<string[]>; key_exchange: Changed<string[]>;
  starttls_states: Changed<string[]>;
  leaf_certificates: Changed<{ fingerprint_sha256: string; subject: string; not_after: string; is_expired: boolean;
                               public_key: string; signature_algorithm: string }[]>;
  sessions: { a: number; b: number };
}

export interface CountDelta { key: string; a: number; b: number; delta: number }

export interface Comparison {
  a: CompareSide; b: CompareSide;
  posture: { score_a: number | null; score_b: number | null; delta: number | null; status_a: string; status_b: string;
             dimensions: { dimension: string; name: string; a: number | null; b: number | null; delta: number | null }[] };
  findings: { new: CompareFinding[]; resolved: CompareFinding[]; persisting: CompareFinding[] };
  assets: CompareAsset[];
  tls_versions: CountDelta[]; cipher_suites: CountDelta[]; protocols: CountDelta[];
  anomalies: { a: number; b: number; delta: number };
  notes: string[];
  method: string;
}
