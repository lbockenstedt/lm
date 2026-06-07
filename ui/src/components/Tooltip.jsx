import React, { useState } from 'react';

const Tooltip = ({ text, children }) => {
  const [visible, setVisible] = useState(false);

  const style = {
    position: 'relative',
    display: 'inline-block',
    cursor: 'pointer'
  };

  const tooltipStyle = {
    position: 'absolute',
    bottom: '125%',
    left: '50%',
    transform: 'translateX(-50%)',
    padding: '8px 12px',
    backgroundColor: '#263040', // HPE Navy from reference
    color: '#fff',
    borderRadius: '4px',
    fontSize: '12px',
    whiteSpace: 'nowrap',
    zIndex: 100,
    opacity: visible ? 1 : 0,
    transition: 'opacity 0.2s ease-in-out',
    pointerEvents: 'none',
    boxShadow: '0 4px 6px rgba(0,0,0,0.1)',
  };

  const arrowStyle = {
    position: 'absolute',
    top: '100%',
    left: '50%',
    marginLeft: '-5px',
    borderWidth: '5px',
    borderStyle: 'solid',
    borderColor: '#263040 transparent transparent transparent'
  };

  return (
    <div style={style} onMouseEnter={() => setVisible(true)} onMouseLeave={() => setVisible(false)}>
      {children}
      {visible && (
        <div style={tooltipStyle}>
          {text}
          <div style={arrowStyle} />
        </div>
      )}
    </div>
  );
};

export default Tooltip;
