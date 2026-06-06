import React from 'react';
import { useTheme } from '../styles/ThemeContext';

const Sidebar = ({ activePage, onNavigate }) => {
  const { theme } = useTheme();
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: '📊' },
    { id: 'resources', label: 'Resources', icon: '💻' },
    { id: 'tenants', label: 'Tenants', icon: '👥' },
    { id: 'security', label: 'Security', icon: '🔒' },
    { id: 'settings', label: 'Settings', icon: '⚙️' },
  ];

  return (
    <nav style={{
      width: '250px',
      height: '100vh',
      backgroundColor: theme.primaryColor,
      color: 'white',
      display: 'flex',
      flexDirection: 'column',
      padding: '20px 0',
      boxSizing: 'border-box'
    }}>
      <div style={{ padding: '0 20px 20px 20px', fontWeight: 'bold', fontSize: '1.2rem' }}>
        Lab Manager
      </div>
      <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
        {menuItems.map(item => (
          <li
            key={item.id}
            onClick={() => onNavigate(item.id)}
            style={{
              padding: '12px 20px',
              cursor: 'pointer',
              backgroundColor: activePage === item.id ? 'rgba(255,255,255,0.2)' : 'transparent',
              transition: 'background 0.2s'
            }}
          >
            <span style={{ marginRight: '10px' }}>{item.icon}</span>
            {item.label}
          </li>
        ))}
      </ul>
    </nav>
  );
};

export default Sidebar;
