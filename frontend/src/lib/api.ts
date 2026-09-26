import axios, { AxiosError } from 'axios';
import type {
  AnalysisResponse, AnomalyDetail, AnomalySummary, CaptureDetail, CaptureSummary, CertificateDetail,
  CertificateSummary, FindingDetail, FindingSummary, PostureResponse, ReportSummary, SessionDetail, SessionSummary,
} from '../types/api';

export const BASE_URL: string = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const apiClient = axios.create({ baseURL: BASE_URL, timeout: 60_000, headers: { Accept: 'application/json' } });

const enc = encodeURIComponent;

/** Human-readable message from an API error (never raw HTML / stack traces). */
export const errorMessage = (err: unknown, fallback = 'Request failed'): string => {
  const e = err as AxiosError<{ detail?: unknown }>;
  const detail = e?.response?.data?.detail;
  if (typeof detail === 'string') return detail.slice(0, 300);
  if (e?.code === 'ERR_NETWORK') return 'Cannot reach the SecureMailScope API. Is the backend running?';
  if (e?.code === 'ECONNABORTED') return 'The request timed out.';
  return fallback;
};

export const uploadPcap = async (file: File, onProgress?: (pct: number) => void) => {
  const form = new FormData();
  form.append('file', file);
  const { data } = await apiClient.post<AnalysisResponse>('/analyze', form, {
    timeout: 15 * 60_000,
    onUploadProgress: (e) => onProgress?.(e.total ? Math.round((e.loaded / e.total) * 100) : 0),
  });
  return data;
};

export const getCaptures = async () => (await apiClient.get<CaptureSummary[]>('/captures')).data;
export const getCapture = async (id: string) => (await apiClient.get<CaptureDetail>(`/captures/${enc(id)}`)).data;
export const getPosture = async (id: string) =>
  (await apiClient.get<PostureResponse>(`/captures/${enc(id)}/posture`)).data;

export const getCaptureSessions = async (id: string) =>
  (await apiClient.get<SessionSummary[]>(`/captures/${enc(id)}/sessions`)).data;
export const getSession = async (id: string) => (await apiClient.get<SessionDetail>(`/sessions/${enc(id)}`)).data;

export const getCaptureFindings = async (id: string) =>
  (await apiClient.get<FindingSummary[]>(`/captures/${enc(id)}/findings`)).data;
export const getFinding = async (id: string) => (await apiClient.get<FindingDetail>(`/findings/${enc(id)}`)).data;
export const setFindingStatus = async (id: string, status: string) =>
  (await apiClient.patch<FindingDetail>(`/findings/${enc(id)}/status`, { status })).data;

export const getCaptureCertificates = async (id: string) =>
  (await apiClient.get<CertificateSummary[]>(`/captures/${enc(id)}/certificates`)).data;
export const getCertificate = async (id: string) =>
  (await apiClient.get<CertificateDetail>(`/certificates/${enc(id)}`)).data;

export const getCaptureAnomalies = async (id: string) =>
  (await apiClient.get<AnomalySummary[]>(`/captures/${enc(id)}/anomalies`)).data;
export const getAnomaly = async (id: number) => (await apiClient.get<AnomalyDetail>(`/anomalies/${id}`)).data;

export const createReport = async (captureId: string, format: 'json' | 'html' | 'pdf') =>
  (await apiClient.post<ReportSummary>(`/captures/${enc(captureId)}/reports`, null, { params: { format } })).data;

/** Report files are served as attachments; the browser downloads rather than renders them. */
export const reportDownloadUrl = (reportId: string) => `${BASE_URL}/reports/${enc(reportId)}/download`;
