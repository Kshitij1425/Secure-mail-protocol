/**
 * API TypeScript Types
 * Corresponds to Pydantic schemas from the FastAPI backend.
 */

// Enums
export type AnalysisStatus = 'pending' | 'processing' | 'completed' | 'failed';
export type PostureStatus = 'excellent' | 'good' | 'fair' | 'poor' | 'critical';
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AnomalyLevel = 'normal' | 'mild' | 'moderate' | 'severe';

// Capture Types
export interface CaptureSummary {
  capture_id: string;
  filename: string;
  file_hash: string;
  upload_timestamp: string;
  analysis_status: AnalysisStatus;
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
  analysis_timestamp: string | null;
  scoring_policy_version: string | null;
  ml_engine_version: string | null;
  ml_anomalies_detected: number;
  sessions_count: number;
  certificates_count: number;
}

// Session Types
export interface SessionSummary {
  session_id: string;
  protocol: string;
  source_ip: string | null;
  source_port: number | null;
  dest_ip: string | null;
  dest_port: number | null;
  start_timestamp: string | null;
  end_timestamp: string | null;
  packet_count: number;
  byte_count: number;
  starttls_state: string | null;
  tls_version: string | null;
  cipher_suite: string | null;
  has_forward_secrecy: boolean;
  has_findings: boolean;
  has_anomaly: boolean;
  anomaly_level: string | null;
}

export interface SessionDetail extends SessionSummary {
  key_exchange: string | null;
  handshake_complete: boolean;
  anomaly_score: number | null;
  findings: string[];
  certificates: string[];
}

// Finding Types
export interface FindingSummary {
  finding_id: string;
  rule_id: string;
  title: string;
  severity: SeverityLevel;
  category: string;
  session_id: string | null;
  confidence: number;
}

export interface FindingDetail extends FindingSummary {
  risk_contribution: number;
  explanation: string | null;
  recommendation: string | null;
  evidence: string | null;
  timestamp: string;
  affected_sessions: string[];
}

// Certificate Types
export interface CertificateSummary {
  fingerprint_sha256: string;
  subject: string;
  issuer: string;
  is_expired: boolean;
  is_self_signed: boolean;
  public_key_algorithm: string;
  public_key_size_bits: number | null;
}

export interface CertificateDetail extends CertificateSummary {
  serial_number: string | null;
  not_before: string | null;
  not_after: string | null;
  signature_algorithm: string | null;
  san_list: string[];
  weak_key: boolean;
  weak_signature: boolean;
  session_id: string | null;
}

// Anomaly Types
export interface AnomalySummary {
  id: number;
  session_id: string;
  is_anomaly: boolean;
  anomaly_score: number | null;
  anomaly_level: AnomalyLevel;
  model_version: string | null;
}

export interface AnomalyDetail extends AnomalySummary {
  capture_id: string;
  explanation: string | null;
  features: Record<string, number>;
  timestamp: string;
}

// Posture Types
export interface DimensionScore {
  dimension: string;
  score: number;
  status: string;
  coverage_percent: number;
  evidence_quality: string;
  sessions_affected: number;
  findings_count: number;
}

export interface TopContributor {
  rule_id: string;
  title: string;
  severity: SeverityLevel;
  sessions_affected: number;
  impact: number;
}

export interface RootCauseGroup {
  root_cause: string;
  severity: SeverityLevel;
  sessions_affected: number;
  findings_count: number;
  rule_ids: string[];
}

export interface PostureResponse {
  overall_score: number;
  status: PostureStatus;
  dimension_scores: DimensionScore[];
  top_contributors: TopContributor[];
  root_cause_groups: RootCauseGroup[];
  scoring_policy_version: string;
  analysis_timestamp: string;
  total_sessions: number;
  sessions_with_findings: number;
  findings_count: number;
  coverage_percent: number;
}

// Report Types
export interface ReportSummary {
  report_id: string;
  capture_id: string;
  report_type: 'json' | 'html' | 'pdf';
  file_size: number;
  created_at: string;
}

// API Response Types
export interface AnalysisResponse {
  capture_id: string;
  status: AnalysisStatus;
  message: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  database_connected: boolean;
}