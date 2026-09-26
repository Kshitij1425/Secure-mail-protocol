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
  findings_count: number;
  anomalies_count: number;
}

export interface CaptureDetail extends CaptureSummary {
  file_size: number;
  file_format: string | null;
  analysis_timestamp: string | null;
  analysis_duration_seconds: number | null;
  capture_start: string | null;
  capture_end: string | null;
  scoring_policy_version: string | null;
  rule_policy_version: string | null;
  ml_engine_version: string | null;
  ml_status: string | null;
  ml_anomalies_detected: number;
  sessions_count: number;
  certificates_count: number;
  reports_count: number;
  severity_counts: Record<string, number>;
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
  features: Record<string, number | string | boolean>;
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
  created_at: string | null;
}

export interface AnalysisResponse {
  capture_id: string;
  status: AnalysisStatus;
  message: string;
}
