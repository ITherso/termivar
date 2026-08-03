import React from 'react';
import { Scan } from '../types';
import './ScansPanel.css';

interface ScansPanelProps {
  scans: Scan[];
  onStartScan?: () => void;
  onViewResults?: (scanId: string) => void;
}

const ScansPanel: React.FC<ScansPanelProps> = ({ scans, onStartScan, onViewResults }) => {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return '#2196F3';
      case 'completed':
        return '#4CAF50';
      case 'failed':
        return '#F44336';
      case 'pending':
        return '#FF9800';
      default:
        return '#9E9E9E';
    }
  };

  const getSeverityPercentage = (scan: Scan) => {
    const total = scan.critical + scan.high + scan.medium + scan.low;
    return total > 0 ? { critical: (scan.critical / total) * 100, high: (scan.high / total) * 100 } : { critical: 0, high: 0 };
  };

  return (
    <div className="scans-panel">
      {scans.length === 0 ? (
        <div className="empty-state">
          <p>No active scans</p>
          {onStartScan && (
            <button type="button" onClick={onStartScan} className="btn-primary">
              Start New Scan
            </button>
          )}
        </div>
      ) : (
        <div className="scans-list">
          {scans.map((scan) => {
            const severity = getSeverityPercentage(scan);
            return (
              <div key={scan.id} className="scan-item">
                <div className="scan-header">
                  <div className="scan-info">
                    <h4>{scan.name}</h4>
                    <p className="target">Target: {scan.target}</p>
                  </div>
                  <div className={`scan-status ${scan.status}`} style={{ color: getStatusColor(scan.status) }}>
                    {scan.status.toUpperCase()}
                  </div>
                </div>

                <div className="scan-vulns">
                  <div className="vuln-badge critical">{scan.critical} Critical</div>
                  <div className="vuln-badge high">{scan.high} High</div>
                  <div className="vuln-badge medium">{scan.medium} Medium</div>
                  <div className="vuln-badge low">{scan.low} Low</div>
                </div>

                <div className="scan-progress">
                  <div className="progress-bar">
                    <div className="progress-critical" style={{ width: `${severity.critical}%` }} />
                    <div className="progress-high" style={{ width: `${severity.high}%` }} />
                  </div>
                </div>

                <div className="scan-footer">
                  <span className="scan-time">
                    {scan.startTime && `Started: ${new Date(scan.startTime).toLocaleString()}`}
                  </span>
                  {scan.status === 'completed' && onViewResults && (
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => onViewResults(scan.id)}
                    >
                      View Results
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default ScansPanel;
