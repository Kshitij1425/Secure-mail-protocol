import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { OverviewPage } from './pages/OverviewPage';
import { FindingsPage } from './pages/FindingsPage';
import { SessionsPage } from './pages/SessionsPage';
import { CertificatesPage } from './pages/CertificatesPage';
import { AnomaliesPage } from './pages/AnomaliesPage';
import { UploadPage } from './pages/UploadPage';
import { CaptureProvider } from './context/CaptureContext';
import { Link } from 'react-router-dom';

const NotFound = () => (
  <div className="text-center py-24 text-slate-400">
    <p className="text-lg font-semibold text-slate-200">Page not found</p>
    <Link to="/" className="text-amber-400 hover:underline text-sm">Back to overview</Link>
  </div>
);

function App() {
  return (
    <CaptureProvider>
      <BrowserRouter>
        <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-amber-500/25">
          <div className="flex h-screen overflow-hidden">
            <Sidebar />
            <div className="flex-1 flex flex-col min-w-0">
              <Header />
              <main className="flex-1 overflow-y-auto p-6 lg:p-8">
              <Routes>
                <Route path="/" element={<OverviewPage />} />
                <Route path="/findings" element={<FindingsPage />} />
                <Route path="/sessions" element={<SessionsPage />} />
                <Route path="/certificates" element={<CertificatesPage />} />
                <Route path="/anomalies" element={<AnomaliesPage />} />
                <Route path="/upload" element={<UploadPage />} />
                <Route path="*" element={<NotFound />} />
              </Routes>
              </main>
            </div>
          </div>
        </div>
      </BrowserRouter>
    </CaptureProvider>
  );
}

export default App;