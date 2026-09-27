import type React from 'react';
import { BrowserRouter, Link, Navigate, Route, Routes } from 'react-router-dom';
import { CaptureProvider } from './context/CaptureContext';
import { Shell } from './components/Shell';
import { ErrorBoundary } from './components/ErrorBoundary';
import { useLocation } from 'react-router-dom';
import { OverviewPage } from './pages/OverviewPage';
import { CapturesPage } from './pages/CapturesPage';
import { FindingsPage } from './pages/FindingsPage';
import { SessionsPage } from './pages/SessionsPage';
import { CertificatesPage } from './pages/CertificatesPage';
import { EvidencePage } from './pages/EvidencePage';
import { AboutPage } from './pages/AboutPage';
import { AnomaliesPage } from './pages/AnomaliesPage';
import { ReportsPage } from './pages/ReportsPage';
import { UploadPage } from './pages/UploadPage';
import { ComparePage } from './pages/ComparePage';

const NotFound = () => (
  <div className="py-16 text-center space-y-2">
    <h1 className="text-xl">Page not found</h1>
    <p className="text-sm text-ink-2">This address is not part of SecureMailScope.</p>
    <Link to="/captures" className="link">Go to step 1: Capture</Link>
  </div>
);

/** Reset the boundary whenever the route changes so navigation recovers from a failed view. */
const RoutedBoundary = ({ children }: { children: React.ReactNode }) => {
  const { pathname } = useLocation();
  return <ErrorBoundary key={pathname}>{children}</ErrorBoundary>;
};

function App() {
  return (
    <CaptureProvider>
      <BrowserRouter>
        <Shell>
          <RoutedBoundary>
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/captures" element={<CapturesPage />} />
            <Route path="/upload" element={<UploadPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/sessions" element={<SessionsPage />} />
            <Route path="/certificates" element={<CertificatesPage />} />
            <Route path="/evidence" element={<EvidencePage />} />
            <Route path="/timeline" element={<Navigate to="/evidence?view=timeline" replace />} />
            <Route path="/about" element={<AboutPage />} />
            <Route path="/anomalies" element={<AnomaliesPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/compare" element={<ComparePage />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
          </RoutedBoundary>
        </Shell>
      </BrowserRouter>
    </CaptureProvider>
  );
}

export default App;
