import React, { useState } from 'react';
import Dashboard from './components/Dashboard';
import './App.css';

type View = 'dashboard' | 'scans' | 'backups' | 'deployments' | 'rbac' | 'audit' | 'sla' | 'dr';

const navigation: Array<{ view: View; label: string }> = [
  { view: 'dashboard', label: '📊 Dashboard' },
  { view: 'scans', label: '🔍 Scan Preview' },
  { view: 'backups', label: '💾 Backup Preview' },
  { view: 'deployments', label: '🚀 Deployment Preview' },
  { view: 'rbac', label: '👥 Access-Control Preview' },
  { view: 'sla', label: '📈 SLA Preview' },
  { view: 'audit', label: '📋 Audit Preview' },
  { view: 'dr', label: '🔁 Recovery Preview' },
];

const placeholders: Record<Exclude<View, 'dashboard'>, { title: string; description: string }> = {
  scans: {
    title: 'Scan Preview',
    description: 'Static placeholder. Scan operations are not implemented in this dashboard preview.',
  },
  backups: {
    title: 'Backup Preview',
    description: 'Static placeholder. Backup operations are not implemented in this dashboard preview.',
  },
  deployments: {
    title: 'Deployment Preview',
    description: 'Static placeholder. Deployment operations are not implemented in this dashboard preview.',
  },
  rbac: {
    title: 'Access-Control Preview',
    description: 'Static placeholder. Authentication and authorization are not implemented.',
  },
  sla: {
    title: 'SLA Preview',
    description: 'Static placeholder. No live service-level data is collected.',
  },
  audit: {
    title: 'Audit Preview',
    description: 'Static placeholder. No live audit events are collected.',
  },
  dr: {
    title: 'Recovery Preview',
    description: 'Static placeholder. Recovery operations are not implemented in this dashboard preview.',
  },
};

const App: React.FC = () => {
  const [activeView, setActiveView] = useState<View>('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="app-container">
      <nav className={`sidebar ${sidebarOpen ? 'open' : 'closed'}`} aria-label="Preview sections">
        <div className="sidebar-header">
          <h2>Termivar</h2>
          <button
            type="button"
            className="sidebar-toggle"
            aria-label={sidebarOpen ? 'Close navigation' : 'Open navigation'}
            onClick={() => setSidebarOpen(!sidebarOpen)}
          >
            {sidebarOpen ? '✕' : '☰'}
          </button>
        </div>

        <ul className="nav-menu">
          {navigation.map(({ view, label }) => (
            <li key={view}>
              <button
                type="button"
                className={`nav-link ${activeView === view ? 'active' : ''}`}
                aria-current={activeView === view ? 'page' : undefined}
                onClick={() => setActiveView(view)}
              >
                {label}
              </button>
            </li>
          ))}
        </ul>

        <div className="sidebar-footer">
          <div className="user-section">
            <div className="user-avatar" aria-hidden="true">◌</div>
            <div className="user-info">
              <p className="user-name">Static preview</p>
              <p className="user-role">No authentication</p>
            </div>
          </div>
        </div>
      </nav>

      <main className="main-content">
        <aside className="preview-notice" role="note">
          <strong>0.10.0-alpha.1 static preview.</strong>{' '}
          This UI is not connected to the Rust API; the API currently exposes only <code>GET /health</code>.
          It has no authentication or security boundary and is not production-ready.
        </aside>

        {activeView === 'dashboard' ? (
          <Dashboard />
        ) : (
          <div className="view-container">
            <h1>{placeholders[activeView].title}</h1>
            <p>{placeholders[activeView].description}</p>
          </div>
        )}
      </main>
    </div>
  );
};

export default App;
