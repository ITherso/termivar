import React from 'react';
import { BackupJob } from '../types';
import './BackupsPanel.css';

interface BackupsPanelProps {
  backups: BackupJob[];
  onCreateBackup?: () => void;
  onRestoreBackup?: (backupId: string) => void;
}

const BackupsPanel: React.FC<BackupsPanelProps> = ({ backups, onCreateBackup, onRestoreBackup }) => {
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Completed':
        return '#4CAF50';
      case 'Running':
        return '#2196F3';
      case 'Failed':
        return '#F44336';
      case 'Pending':
        return '#FF9800';
      default:
        return '#9E9E9E';
    }
  };

  return (
    <div className="backups-panel">
      {backups.length === 0 ? (
        <div className="empty-state">
          <p>No recent backups</p>
          {onCreateBackup && (
            <button type="button" onClick={onCreateBackup} className="btn-primary">
              Create Backup
            </button>
          )}
        </div>
      ) : (
        <div className="backups-list">
          {backups.map((backup) => (
            <div key={backup.id} className="backup-item">
              <div className="backup-header">
                <div className="backup-info">
                  <h4>{backup.name}</h4>
                  <p className="backup-type">{backup.type} Backup</p>
                </div>
                <div className="backup-status" style={{ color: getStatusColor(backup.status) }}>
                  {backup.status}
                </div>
              </div>

              <div className="backup-stats">
                <div className="stat">
                  <span className="label">Original Size:</span>
                  <span className="value">{formatBytes(backup.dataSize)}</span>
                </div>
                <div className="stat">
                  <span className="label">Compressed Size:</span>
                  <span className="value">{formatBytes(backup.compressedSize)}</span>
                </div>
                <div className="stat">
                  <span className="label">Compression:</span>
                  <span className="value">{(backup.compressionRatio * 100).toFixed(1)}%</span>
                </div>
                <div className="stat">
                  <span className="label">Retention:</span>
                  <span className="value">{backup.retentionDays} days</span>
                </div>
              </div>

              <div className="backup-timeline">
                <div className="timeline-item">
                  <span className="label">Started:</span>
                  <span className="time">{new Date(backup.startTime).toLocaleString()}</span>
                </div>
                {backup.endTime && (
                  <div className="timeline-item">
                    <span className="label">Completed:</span>
                    <span className="time">{new Date(backup.endTime).toLocaleString()}</span>
                  </div>
                )}
              </div>

              {backup.status === 'Completed' && onRestoreBackup && (
                <div className="backup-actions">
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={() => onRestoreBackup(backup.id)}
                  >
                    Restore
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default BackupsPanel;
