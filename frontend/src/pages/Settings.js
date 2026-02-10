import React from 'react';
import { User, Shield, Server, Globe } from 'lucide-react';

const Settings = () => {
  // Static data for now - in V2 we can fetch this from an API
  const user = localStorage.getItem('username') || 'Admin User';

  return (
    <div style={{ padding: '30px', animation: 'fadeIn 0.5s' }}>
      <h2 style={{ color: '#2c3e50', borderBottom: '2px solid #3498db', paddingBottom: '10px' }}>
        ⚙️ System Settings
      </h2>

      <div style={{ marginTop: '30px', display: 'grid', gap: '20px' }}>
        
        {/* PROFILE CARD */}
        <div style={styles.section}>
          <h3 style={styles.header}><User size={20} style={{ marginRight: '10px' }} /> User Profile</h3>
          <div style={{ display: 'flex', alignItems: 'center', padding: '10px' }}>
            <div style={{ width: '50px', height: '50px', background: '#3498db', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white', fontWeight: 'bold', fontSize: '20px', marginRight: '15px' }}>
              {user.charAt(0).toUpperCase()}
            </div>
            <div>
              <p style={{ margin: 0, fontWeight: 'bold', fontSize: '16px' }}>{user}</p>
              <p style={{ margin: 0, color: '#7f8c8d', fontSize: '13px' }}>Administrator</p>
            </div>
          </div>
        </div>

        {/* SYSTEM STATUS */}
        <div style={styles.section}>
          <h3 style={styles.header}><Server size={20} style={{ marginRight: '10px' }} /> System Status</h3>
          <div style={styles.row}>
            <span>Backend Connection</span>
            <span style={styles.badgeGreen}>Online (Render Cloud)</span>
          </div>
          <div style={styles.row}>
            <span>Database</span>
            <span style={styles.badgeGreen}>Connected (MongoDB Atlas)</span>
          </div>
          <div style={styles.row}>
            <span>Vulnerability Database</span>
            <span style={styles.badgeBlue}>NVD API V2.0</span>
          </div>
        </div>

        {/* APP INFO */}
        <div style={styles.section}>
          <h3 style={styles.header}><Globe size={20} style={{ marginRight: '10px' }} /> About Application</h3>
          <p style={{ color: '#7f8c8d', fontSize: '14px', lineHeight: '1.6' }}>
            ANSAS (Automated Network Security Assessment System) Pro<br/>
            Version: 1.0.0 (Cloud Release)<br/>
            Developed by: ANSAS Team<br/>
            &copy; 2026 All Rights Reserved.
          </p>
        </div>

      </div>
    </div>
  );
};

const styles = {
  section: { background: 'white', padding: '25px', borderRadius: '10px', boxShadow: '0 4px 15px rgba(0,0,0,0.05)' },
  header: { margin: '0 0 20px 0', color: '#2c3e50', display: 'flex', alignItems: 'center', fontSize: '18px' },
  row: { display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid #f0f0f0' },
  badgeGreen: { background: '#e8f8f5', color: '#27ae60', padding: '2px 10px', borderRadius: '10px', fontSize: '12px', fontWeight: 'bold' },
  badgeBlue: { background: '#ebf5fb', color: '#3498db', padding: '2px 10px', borderRadius: '10px', fontSize: '12px', fontWeight: 'bold' }
};

export default Settings;