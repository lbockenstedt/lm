import React from 'react';
import { useTheme } from '../styles/ThemeContext';

const Widget = ({ title, content }) => (
  <div style={{
    padding: '20px',
    backgroundColor: 'white',
    borderRadius: '8px',
    boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
    border: '1px solid #eee'
  }}>
    <h3 style={{ margin: '0 0 15px 0', fontSize: '1rem' }}>{title}</h3>
    <div>{content}</div>
  </div>
);

const Dashboard = ({ hubState }) => {
  const { theme } = useTheme();

  // Dynamically generate widgets based on active modules
  const widgets = [];
  if (hubState.active_connections.length > 0) {
    widgets.push({
      title: 'Active Spokes',
      content: <div>{hubState.active_connections.length} spokes currently connected.</div>
    });
  }

  // Heartbeat status widget
  const statuses = hubState.heartbeats || {};
  const redCount = Object.values(statuses).filter(s => s === 'RED').length;
  const yellowCount = Object.values(statuses).filter(s => s === 'YELLOW').length;
  const greenCount = Object.values(statuses).filter(s => s === 'GREEN').length;

  widgets.push({
    title: 'System Health',
    content: (
      <div style={{ display: 'flex', gap: '10px' }}>
        <span style={{ color: 'green' }}>● {greenCount} Healthy</span>
        <span style={{ color: 'orange' }}>● {yellowCount} Warning</span>
        <span style={{ color: 'red' }}>● {redCount} Offline</span>
      </div>
    )
  });

  return (
    <div style={{ padding: '20px', backgroundColor: '#f5f7f9', minHeight: 'calc(100vh - 60px)' }}>
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
        gap: '20px'
      }}>
        {widgets.map((w, i) => <Widget key={i} title={w.title} content={w.content} />)}
      </div>
    </div>
  );
};

export default Dashboard;
