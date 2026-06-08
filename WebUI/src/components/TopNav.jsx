import React from 'react';
import { useTheme } from '../styles/ThemeContext';

const TopNav = ({ title, actions }) => {
  const { theme } = useTheme();

  return (
    <header style={{
      height: '60px',
      backgroundColor: theme.secondaryColor,
      borderBottom: '1px solid #ddd',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 20px',
      boxSizing: 'border-box'
    }}>
      <h2 style={{ margin: 0, fontSize: '1.1rem' }}>{title}</h2>
      <div style={{ display: 'flex', gap: '10px' }}>
        {actions.map((action, index) => (
          <button
            key={index}
            onClick={action.onClick}
            style={{
              padding: '6px 12px',
              borderRadius: theme.borderRadius,
              backgroundColor: theme.primaryColor,
              color: 'white',
              border: 'none',
              cursor: 'pointer'
            }}
          >
            {action.label}
          </button>
        ))}
      </div>
    </header>
  );
};

export default TopNav;
