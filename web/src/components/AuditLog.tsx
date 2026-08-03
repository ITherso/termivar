import React, { useState } from 'react';
import { AuditEvent } from '../types';
import './AuditLog.css';

interface AuditLogProps {
  events: AuditEvent[];
}

const AuditLog: React.FC<AuditLogProps> = ({ events }) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'Critical':
        return '#ff4444';
      case 'Error':
        return '#ff9800';
      case 'Warning':
        return '#ffc107';
      default:
        return '#4caf50';
    }
  };

  return (
    <div className="audit-log">
      <table className="audit-table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Level</th>
            <th>Category</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <React.Fragment key={event.id}>
              <tr
                className={`audit-row level-${event.level.toLowerCase()}`}
                onClick={() => setExpandedId(expandedId === event.id ? null : event.id)}
              >
                <td>{new Date(event.timestamp).toLocaleString()}</td>
                <td>
                  <span className="level-badge" style={{ backgroundColor: getLevelColor(event.level) }}>
                    {event.level}
                  </span>
                </td>
                <td>{event.category}</td>
                <td>{event.actor}</td>
                <td>{event.action}</td>
                <td>
                  <span className={`status ${event.status}`}>{event.status}</span>
                </td>
              </tr>
              {expandedId === event.id && (
                <tr className="audit-details">
                  <td colSpan={6}>
                    <div className="details-content">
                      <p><strong>Resource:</strong> {event.resource}</p>
                      {event.sourceIP && <p><strong>Source IP:</strong> {event.sourceIP}</p>}
                      {Object.keys(event.details).length > 0 && (
                        <div className="details-map">
                          <strong>Details:</strong>
                          {Object.entries(event.details).map(([key, value]) => (
                            <div key={key} className="detail-item">
                              {key}: {value}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </td>
                </tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default AuditLog;
