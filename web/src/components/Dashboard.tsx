import React from 'react';
import { DashboardData } from '../types';
import StatusCard from './StatusCard';
import MetricsChart from './MetricsChart';
import AuditLog from './AuditLog';
import SLAStatus from './SLAStatus';
import ScansPanel from './ScansPanel';
import BackupsPanel from './BackupsPanel';

const PREVIEW_TIMESTAMP = new Date('2026-01-01T00:00:00Z');

const PREVIEW_DATA: DashboardData = {
  systemStatus: {
    status: 'stopped',
    uptime: 0,
    version: '0.10.0-alpha.2',
    lastUpdate: PREVIEW_TIMESTAMP,
    healthy: false,
  },
  healthCheck: {
    cpu: 0,
    memory: 0,
    disk: 0,
    network: 0,
    timestamp: PREVIEW_TIMESTAMP,
  },
  slaMetrics: [],
  recentAuditEvents: [],
  activeScans: [],
  recentBackups: [],
  deployments: [],
  slaViolations: [],
};

const Dashboard: React.FC = () => {
  const data = PREVIEW_DATA;

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>Termivar Dashboard</h1>
        <div className="header-info">
          <span className="version">0.10.0-alpha.2 Preview</span>
          <span className="last-update">Illustrative static data</span>
        </div>
      </header>

      <div className="dashboard-grid">
        <section className="status-overview">
          <h2>Illustrative System Overview</h2>
          <div className="status-cards">
            <StatusCard
              title="Preview Status"
              status={data.systemStatus.status}
              value="Not connected"
              details={`Illustrative uptime: ${formatUptime(data.systemStatus.uptime)}`}
            />
            <StatusCard
              title="Illustrative CPU"
              status="stopped"
              value={`${data.healthCheck.cpu.toFixed(1)}%`}
              details="Static placeholder"
            />
            <StatusCard
              title="Illustrative Memory"
              status="stopped"
              value={`${data.healthCheck.memory.toFixed(1)}%`}
              details="Static placeholder"
            />
            <StatusCard
              title="Illustrative Disk"
              status="stopped"
              value={`${data.healthCheck.disk.toFixed(1)}%`}
              details="Static placeholder"
            />
          </div>
        </section>

        <section className="sla-section">
          <h2>Illustrative SLA Data</h2>
          <SLAStatus metrics={data.slaMetrics} violations={data.slaViolations} />
        </section>

        <section className="metrics-section">
          <h2>Illustrative Resource Data</h2>
          <MetricsChart data={data.healthCheck} />
        </section>

        <section className="scans-section">
          <h2>Illustrative Scan Data</h2>
          <ScansPanel scans={data.activeScans} />
        </section>

        <section className="backups-section">
          <h2>Illustrative Backup Data</h2>
          <BackupsPanel backups={data.recentBackups} />
        </section>

        <section className="audit-section">
          <h2>Illustrative Audit Data</h2>
          <AuditLog events={data.recentAuditEvents} />
        </section>
      </div>

      <footer className="dashboard-footer">
        <p>Termivar 0.10.0-alpha.2 Dashboard Preview</p>
        <p>Static sample data · No Rust API connection · No authentication · Not production-ready</p>
      </footer>
    </div>
  );
};

const formatUptime = (uptime: number): string => {
  const days = Math.floor(uptime / 86400);
  const hours = Math.floor((uptime % 86400) / 3600);
  return `${days}d ${hours}h`;
};

export default Dashboard;
