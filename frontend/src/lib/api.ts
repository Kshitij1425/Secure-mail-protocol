import axios, { AxiosError } from 'axios';
import type {
  AnalysisResponse, Annotation, AnnotationTarget, AnomalyDetail, AnomalySummary, CaptureDetail, CaptureSummary, CertificateDetail,
  CertificateInventoryItem, CertificateSummary, Comparison, EvidenceChain, FindingDetail, FindingSummary,
  PolicyProfile, PostureResponse, ReportSummary, SessionDetail, SessionSummary, TimelineEvent, TrendPoint,
} from '../types/api';

export const BASE_URL: string = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const apiClient = axios.create({ baseURL: BASE_URL, timeout: 60_000, headers: { Accept: 'application/json' } });

const enc = encodeURIComponent;

/** Human-readable message from an API error (never raw HTML / stack traces). */
export const errorMessage = (err: unknown, fallback = 'Request failed'): string => {
  const e = err as AxiosError<{ detail?: unknown }>;
  const detail = e?.response?.data?.detail;
  if (typeof detail === 'string') return detail.slice(0, 300);
  if (e?.code === 'ERR_NETWORK') return 'The SecureMailScope API is not reachable. Start the backend and retry.';
  if (e?.code === 'ECONNABORTED') return 'The request timed out.';
  return fallback;
};

export const getPolicies = async () => (await apiClient.get<PolicyProfile[]>('/policies')).data;

export const uploadPcap = async (file: File, policy: string, onProgress?: (pct: number) => void) => {
  const form = new FormData();
  form.append('file', file);
  form.append('policy', policy);
  const { data } = await apiClient.post<AnalysisResponse>('/analyze', form, {
    timeout: 15 * 60_000,
    onUploadProgress: (e) => onProgress?.(e.total ? Math.round((e.loaded / e.total) * 100) : 0),
  });
  return data;
};

export const reanalyze = async (captureId: string, policy: string) =>
  (await apiClient.post<AnalysisResponse>(`/captures/${enc(captureId)}/reanalyze`, null, { params: { policy }, timeout: 15 * 60_000 })).data;

export const getCaptures = async () => (await apiClient.get<CaptureSummary[]>('/captures')).data;
export const getCapture = async (id: string) => (await apiClient.get<CaptureDetail>(`/captures/${enc(id)}`)).data;
export const getPosture = async (id: string) =>
  (await apiClient.get<PostureResponse>(`/captures/${enc(id)}/posture`)).data;
export const getTimeline = async (id: string, sessionId?: string) =>
  (await apiClient.get<TimelineEvent[]>(`/captures/${enc(id)}/timeline`, { params: sessionId ? { session_id: sessionId } : {} })).data;
export const getCertificateInventory = async (id: string) =>
  (await apiClient.get<CertificateInventoryItem[]>(`/captures/${enc(id)}/certificate-inventory`)).data;

export const getCaptureSessions = async (id: string) =>
  (await apiClient.get<SessionSummary[]>(`/captures/${enc(id)}/sessions`)).data;
export const getSession = async (id: string) => (await apiClient.get<SessionDetail>(`/sessions/${enc(id)}`)).data;

export const getCaptureFindings = async (id: string) =>
  (await apiClient.get<FindingSummary[]>(`/captures/${enc(id)}/findings`)).data;
export const getFinding = async (id: string) => (await apiClient.get<FindingDetail>(`/findings/${enc(id)}`)).data;
export const getFindingChain = async (id: string) =>
  (await apiClient.get<EvidenceChain>(`/findings/${enc(id)}/chain`)).data;
export const setFindingStatus = async (id: string, status: string) =>
  (await apiClient.patch<FindingDetail>(`/findings/${enc(id)}/status`, { status })).data;

export const getCaptureCertificates = async (id: string) =>
  (await apiClient.get<CertificateSummary[]>(`/captures/${enc(id)}/certificates`)).data;
export const getCertificate = async (id: string) =>
  (await apiClient.get<CertificateDetail>(`/certificates/${enc(id)}`)).data;

export const getCaptureAnomalies = async (id: string) =>
  (await apiClient.get<AnomalySummary[]>(`/captures/${enc(id)}/anomalies`)).data;
export const getAnomaly = async (id: number) => (await apiClient.get<AnomalyDetail>(`/anomalies/${id}`)).data;

export const getCompare = async (a: string, b: string) =>
  (await apiClient.get<Comparison>('/compare', { params: { a, b } })).data;

export interface ReportPreview {
  html: string; sha256: string; sections: { anchor: string; number: string; title: string }[];
  mode: 'RAW' | 'REDACTED'; policy_profile: string; score: number | null; status: string; findings: number;
  capture_sha256: string; filename: string; selected_annotations: number;
}
export const getReportPreview = async (captureId: string, redact: boolean) =>
  (await apiClient.get<ReportPreview>(`/captures/${enc(captureId)}/report-preview`, { params: { redact } })).data;

export const getTrend = async (captureId: string) =>
  (await apiClient.get<TrendPoint[]>(`/captures/${enc(captureId)}/trend`)).data;

/* Analyst annotations: notes and "include in investigation report" selections. */
export const getAnnotations = async (captureId: string, targetType?: AnnotationTarget, targetId?: string) =>
  (await apiClient.get<Annotation[]>(`/captures/${enc(captureId)}/annotations`,
    { params: { target_type: targetType, target_id: targetId } })).data;
export const createAnnotation = async (captureId: string, body: { target_type: AnnotationTarget; target_id: string; text: string; include_in_report: boolean }) =>
  (await apiClient.post<Annotation>(`/captures/${enc(captureId)}/annotations`, body)).data;
export const updateAnnotation = async (id: number, body: { text?: string; include_in_report?: boolean }) =>
  (await apiClient.patch<Annotation>(`/annotations/${id}`, body)).data;
export const deleteAnnotation = async (id: number) => { await apiClient.delete(`/annotations/${id}`); };

export const getReports = async (captureId: string) =>
  (await apiClient.get<ReportSummary[]>('/reports', { params: { capture_id: captureId } })).data;
export const createReport = async (captureId: string, format: 'json' | 'html' | 'pdf', redact: boolean) =>
  (await apiClient.post<ReportSummary>(`/captures/${enc(captureId)}/reports`, null, { params: { format, redact } })).data;

/** Download URLs: the API serves these as attachments; the browser saves rather than renders them. */
export const reportDownloadUrl = (reportId: string) => `${BASE_URL}/reports/${enc(reportId)}/download`;
export const bundleUrl = (captureId: string, redact: boolean) =>
  `${BASE_URL}/captures/${enc(captureId)}/bundle?redact=${redact}`;
export const stixUrl = (captureId: string, redact: boolean) =>
  `${BASE_URL}/captures/${enc(captureId)}/stix?redact=${redact}`;

export const download = (url: string) => {
  const a = document.createElement('a');
  a.href = url;
  a.rel = 'noopener';
  a.click();
};
