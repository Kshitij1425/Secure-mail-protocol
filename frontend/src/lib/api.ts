import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  headers: {
    'Accept': 'application/json',
  },
});

// Upload PCAP
export const uploadPcap = async (file: File) => {
  const formData = new FormData();
  formData.append('file', file);
  const { data } = await apiClient.post('/analyze', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return data;
};

// Capture endpoints
export const getCaptures = async (status?: string) => {
  const params = status ? { status } : {};
  const { data } = await apiClient.get('/captures', { params });
  return data;
};

export const getCapture = async (captureId: string) => {
  const { data } = await apiClient.get(`/captures/${captureId}`);
  return data;
};

// Session endpoints
export const getCaptureSessions = async (captureId: string) => {
  const { data } = await apiClient.get(`/captures/${captureId}/sessions`);
  return data;
};

export const getSessions = async (filters?: { capture_id?: string; protocol?: string }) => {
  const { data } = await apiClient.get('/sessions', { params: filters });
  return data;
};

export const getSession = async (sessionId: string) => {
  const { data } = await apiClient.get(`/sessions/${sessionId}`);
  return data;
};

// Finding endpoints
export const getFindings = async (filters?: { capture_id?: string; severity?: string }) => {
  const { data } = await apiClient.get('/findings', { params: filters });
  return data;
};

export const getFinding = async (findingId: string) => {
  const { data } = await apiClient.get(`/findings/${findingId}`);
  return data;
};

// Anomaly endpoints
export const getAnomalies = async (filters?: { capture_id?: string; is_anomaly?: boolean }) => {
  const { data } = await apiClient.get('/anomalies', { params: filters });
  return data;
};

export const getAnomaly = async (anomalyId: number) => {
  const { data } = await apiClient.get(`/anomalies/${anomalyId}`);
  return data;
};

// Certificate endpoints
export const getCertificates = async (filters?: { capture_id?: string; session_id?: string }) => {
  const { data } = await apiClient.get('/certificates', { params: filters });
  return data;
};

export const getCertificate = async (fingerprint: string) => {
  const { data } = await apiClient.get(`/certificates/${fingerprint}`);
  return data;
};

// Posture endpoint
export const getPosture = async (captureId: string) => {
  const { data } = await apiClient.get(`/captures/${captureId}/posture`);
  return data;
};

// Report endpoints
export const getReports = async (captureId?: string) => {
  const params = captureId ? { capture_id: captureId } : {};
  const { data } = await apiClient.get('/reports', { params });
  return data;
};

export const getReport = async (reportId: string) => {
  const { data } = await apiClient.get(`/reports/${reportId}`);
  return data;
};

export const downloadReport = (reportId: string) => {
  window.open(`${BASE_URL}/reports/${reportId}/download`, '_blank');
};