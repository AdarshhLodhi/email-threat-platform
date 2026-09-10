import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import { Shield, LayoutDashboard, Search, FileText } from 'lucide-react';
import Dashboard from './pages/Dashboard';
import UploadInvestigation from './pages/UploadInvestigation';
import CaseManagement from './pages/CaseManagement';
import CaseDetails from './pages/CaseDetails';

function Sidebar() {
  const location = useLocation();
  
  const navItems = [
    { path: '/', name: 'Dashboard', icon: <LayoutDashboard size={20} /> },
    { path: '/investigate', name: 'New Investigation', icon: <Search size={20} /> },
    { path: '/cases', name: 'Case Management', icon: <FileText size={20} /> },
  ];

  return (
    <div className="glass-panel" style={{ width: '260px', flexShrink: 0, height: '100%', display: 'flex', flexDirection: 'column', borderRight: 'none', borderRadius: '0', borderTopRightRadius: '1rem', borderBottomRightRadius: '1rem' }}>
      <div className="p-6 flex items-center gap-2 mb-4">
        <Shield size={28} className="text-primary-color" style={{ color: 'var(--primary-color)' }} />
        <h2 className="text-gradient m-0" style={{ fontSize: '1.25rem', lineHeight: '1.2' }}>ThreatIntel</h2>
      </div>
      
      <nav style={{ flex: 1, padding: '0 1rem' }}>
        <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {navItems.map((item) => {
            const isActive = location.pathname === item.path || (item.path !== '/' && location.pathname.startsWith(item.path));
            return (
              <li key={item.path}>
                <Link 
                  to={item.path}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.75rem',
                    padding: '0.75rem 1rem',
                    borderRadius: 'var(--radius-md)',
                    color: isActive ? 'var(--primary-color)' : 'var(--text-muted)',
                    background: isActive ? 'rgba(37, 99, 235, 0.1)' : 'transparent',
                    borderLeft: isActive ? '3px solid var(--primary-color)' : '3px solid transparent',
                    textDecoration: 'none',
                    fontWeight: 500,
                    transition: 'all var(--transition-fast)'
                  }}
                  onMouseEnter={(e) => {
                    if (!isActive) e.currentTarget.style.background = 'rgba(0, 0, 0, 0.03)';
                  }}
                  onMouseLeave={(e) => {
                    if (!isActive) e.currentTarget.style.background = 'transparent';
                  }}
                >
                  {item.icon}
                  {item.name}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
    </div>
  );
}

function App() {
  return (
    <Router>
      <div className="app-container">
        <Sidebar />
        <main className="main-content">
          <div className="scroll-area">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/investigate" element={<UploadInvestigation />} />
              <Route path="/cases" element={<CaseManagement />} />
              <Route path="/cases/:id" element={<CaseDetails />} />
            </Routes>
          </div>
        </main>
      </div>
    </Router>
  );
}

export default App;
