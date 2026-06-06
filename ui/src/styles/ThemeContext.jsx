import React, { createContext, useContext, useState } from 'react';

const ThemeContext = createContext();

export const ThemeProvider = ({ children }) => {
  const [theme, setTheme] = useState({
    primaryColor: '#004a99', // HPE Blue
    secondaryColor: '#ffffff',
    logoUrl: '/logo-default.png',
    fontSize: '14px',
    borderRadius: '4px'
  });

  // This would be called when the Hub identifies the tenant
  const updateTenantTheme = (tenantTheme) => {
    setTheme(prev => ({ ...prev, ...tenantTheme }));
  };

  return (
    <ThemeContext.Provider value={{ theme, updateTenantTheme }}>
      <div style={{
        '--primary-color': theme.primaryColor,
        '--secondary-color': theme.secondaryColor,
        '--border-radius': theme.borderRadius,
        fontSize: theme.fontSize
      }}>
        {children}
      </div>
    </ThemeContext.Provider>
  );
};

export const useTheme = () => useContext(ThemeContext);
