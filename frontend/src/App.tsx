import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { OverviewPage } from './pages/OverviewPage';
import { FindingsPage } from './pages/FindingsPage';
import { SessionsPage } from './pages/SessionsPage';
import { CertificatesPage } from './pages/CertificatesPage';
import { AnomaliesPage } from './pages/AnomaliesPage';
import { UploadPage } from './pages/UploadPage';
import { CaptureProvider } from './context/CaptureContext';

function App() {
  return (
    <CaptureProvider>
      <BrowserRouter>
        <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-amber-500/25">
          <div className="flex h-screen overflow-hidden">
            <Sidebar />
            <main className="flex-1 overflow-y-auto p-6 lg:p-8">
              <Routes>
                <Route path="/" element={<OverviewPage />} />
                <Route path="/findings" element={<FindingsPage />} />
                <Route path="/sessions" element={<SessionsPage />} />
                <Route path="/certificates" element={<CertificatesPage />} />
                <Route path="/anomalies" element={<AnomaliesPage />} />
                <Route path="/upload" element={<UploadPage />} />
              </Routes>
            </main>
          </div>
        </div>
      </BrowserRouter>
    </CaptureProvider>
  );
}

export default App;