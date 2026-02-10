import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, History, FileText, Settings, LogOut, Shield } from 'lucide-react';

const Sidebar = ({ onLogout }) => {
  const location = useLocation();

  const menuItems = [
    { path: '/', icon: <LayoutDashboard size={20} />, label: 'Dashboard' },
    { path: '/history', icon: <History size={20} />, label: 'Scan History' },
    { path: '/reports', icon: <FileText size={20} />, label: 'Reports' },
    { path: '/settings', icon: <Settings size={20} />, label: 'Settings' },
  ];

  return (
    <div style={{ 
      width: '240px', 
      height: '100vh', 
      background: '#2c3e50', 
      color: 'white', 
      position: 'fixed', 
      left: 0, 
      top: 0, 
      display: 'flex', 
      flexDirection: 'column',
      boxShadow: '4px 0 10px rgba(0,0,0,0.1)',
      zIndex: 1000
    }}>
      
      {/* LOGO AREA */}
      <div style={{ padding: '25px', display: 'flex', alignItems: 'center', borderBottom: '1px solid #34495e' }}>
        <Shield size={28} color="#3498db" style={{ marginRight: '10px' }} />
        <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 'bold' }}>ANSAS <span style={{ color: '#3498db' }}>Pro</span></h2>
      </div>

      {/* MENU ITEMS */}
      <div style={{ flex: 1, padding: '20px 0' }}>
        {menuItems.map((item) => {
          const isActive = location.pathname === item.path;
          return (
            <Link 
              key={item.path} 
              to={item.path} 
              style={{ 
                display: 'flex', 
                alignItems: 'center', 
                padding: '15px 25px', 
                textDecoration: 'none', 
                color: isActive ? '#fff' : '#bdc3c7',
                background: isActive ? '#34495e' : 'transparent',
                borderLeft: isActive ? '4px solid #3498db' : '4px solid transparent',
                transition: 'all 0.2s ease-in-out',
                fontWeight: isActive ? 'bold' : 'normal'
              }}
            >
              <div style={{ marginRight: '12px', color: isActive ? '#3498db' : '#bdc3c7' }}>
                {item.icon}
              </div>
              <span>{item.label}</span>
            </Link>
          );
        })}
      </div>

      {/* LOGOUT BUTTON */}
      <div style={{ padding: '20px', borderTop: '1px solid #34495e' }}>
        <button 
          onClick={onLogout}
          style={{ 
            width: '100%', 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center', 
            background: '#c0392b', // Red color for logout
            color: 'white', 
            border: 'none', 
            padding: '12px', 
            borderRadius: '5px', 
            cursor: 'pointer',
            fontWeight: 'bold',
            transition: 'background 0.3s'
          }}
          onMouseOver={(e) => e.target.style.background = '#e74c3c'}
          onMouseOut={(e) => e.target.style.background = '#c0392b'}
        >
          <LogOut size={18} style={{ marginRight: '8px' }} />
          Sign Out
        </button>
      </div>

    </div>
  );
};

export default Sidebar;