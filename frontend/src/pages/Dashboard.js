import React from 'react';
import { 
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer, 
  BarChart, Bar, XAxis, YAxis, CartesianGrid 
} from 'recharts';
import { Upload, Activity, AlertTriangle, Shield, Server, CheckCircle } from 'lucide-react';

const Dashboard = ({ file, setFile, handleUpload, loading, error, data }) => {

  // --- HELPER: Process Data for Charts ---
  const processCharts = () => {
    if (!data) return { pieData: [], barData: [] };

    let critical = 0, high = 0, medium = 0, low = 0;
    const portCounts = {};

    data.forEach(host => {
      host.services.forEach(svc => {
        // 1. Severity Counts
        if (svc.vulnerabilities) {
          svc.vulnerabilities.forEach(v => {
            if (v.cvss_score >= 9.0) critical++;
            else if (v.cvss_score >= 7.0) high++;
            else if (v.cvss_score >= 4.0) medium++;
            else low++;
          });
        }
        // 2. Port Counts (for Bar Chart)
        const port = svc.port;
        portCounts[port] = (portCounts[port] || 0) + 1;
      });
    });

    const pieData = [
      { name: 'Critical', value: critical, color: '#c0392b' }, // Dark Red
      { name: 'High', value: high, color: '#e67e22' },     // Orange
      { name: 'Medium', value: medium, color: '#f1c40f' }, // Yellow
      { name: 'Low', value: low, color: '#27ae60' },      // Green
    ].filter(i => i.value > 0);

    const barData = Object.keys(portCounts).map(port => ({
      name: `Port ${port}`,
      count: portCounts[port]
    })).slice(0, 5); // Top 5 ports

    return { pieData, barData };
  };

  const { pieData, barData } = processCharts();

  return (
    <div style={{ padding: '30px', animation: 'fadeIn 0.5s' }}>
      
      {/* HEADER */}
      <div style={{ marginBottom: '30px' }}>
        <h2 style={{ color: '#2c3e50', margin: 0, display: 'flex', alignItems: 'center' }}>
          <Activity style={{ marginRight: '10px', color: '#3498db' }} /> 
          Security Operations Center
        </h2>
        <p style={{ color: '#7f8c8d', marginLeft: '35px' }}>Real-time Vulnerability Assessment Dashboard</p>
      </div>

      {/* UPLOAD AREA */}
      <div style={{ background: 'white', padding: '30px', borderRadius: '15px', boxShadow: '0 4px 15px rgba(0,0,0,0.05)', textAlign: 'center', marginBottom: '30px' }}>
        <div style={{ border: '2px dashed #3498db', padding: '40px', borderRadius: '10px', backgroundColor: '#f9fbfd' }}>
          <Upload size={48} color="#3498db" style={{ marginBottom: '15px' }} />
          <h3 style={{ color: '#2c3e50' }}>Upload Nmap XML Scan</h3>
          <p style={{ color: '#95a5a6' }}>Drag and drop your file here or click to browse</p>
          
          <input 
            type="file" 
            accept=".xml" 
            onChange={(e) => setFile(e.target.files[0])} 
            style={{ display: 'block', margin: '20px auto' }} 
          />
          
          <button 
            onClick={handleUpload} 
            disabled={loading}
            style={{ 
              backgroundColor: loading ? '#95a5a6' : '#2c3e50', 
              color: 'white', padding: '12px 30px', border: 'none', borderRadius: '5px', fontSize: '16px', cursor: loading ? 'not-allowed' : 'pointer', fontWeight: 'bold', transition: '0.3s'
            }}
          >
            {loading ? "Analyzing Target..." : "Run Security Analysis"}
          </button>
          
          {error && <div style={{ marginTop: '15px', color: '#c0392b', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><AlertTriangle size={16} style={{marginRight:5}}/> {error}</div>}
        </div>
      </div>

      {/* ANALYTICS SECTION */}
      {data && (
        <>
          {/* KPI CARDS */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '20px', marginBottom: '30px' }}>
            <div style={styles.card}>
              <Server size={30} color="#3498db" />
              <h3>{data.length}</h3>
              <p>Assets Discovered</p>
            </div>
            <div style={styles.card}>
              <AlertTriangle size={30} color="#e74c3c" />
              <h3>{pieData.reduce((a, b) => a + b.value, 0)}</h3>
              <p>Total Vulnerabilities</p>
            </div>
            <div style={styles.card}>
              <Shield size={30} color="#27ae60" />
              <h3>Secure</h3>
              <p>System Status</p>
            </div>
          </div>

          {/* CHARTS ROW */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '30px' }}>
            
            {/* Pie Chart */}
            <div style={{ background: 'white', padding: '20px', borderRadius: '10px', boxShadow: '0 4px 15px rgba(0,0,0,0.05)' }}>
              <h3 style={{ color: '#2c3e50', borderBottom: '1px solid #eee', paddingBottom: '10px' }}>Severity Distribution</h3>
              <div style={{ height: '300px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label>
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Detailed Findings List */}
            <div style={{ background: 'white', padding: '20px', borderRadius: '10px', boxShadow: '0 4px 15px rgba(0,0,0,0.05)', maxHeight: '380px', overflowY: 'auto' }}>
              <h3 style={{ color: '#2c3e50', borderBottom: '1px solid #eee', paddingBottom: '10px' }}>Live Findings Feed</h3>
              {data.map((host, idx) => (
                <div key={idx} style={{ marginBottom: '15px', paddingBottom: '15px', borderBottom: '1px solid #f0f0f0' }}>
                  <div style={{ display: 'flex', alignItems: 'center', marginBottom: '5px' }}>
                    <Server size={16} color="#7f8c8d" style={{ marginRight: '8px' }} />
                    <strong style={{ color: '#34495e' }}>{host.ip_address}</strong>
                  </div>
                  <ul style={{ paddingLeft: '28px', marginTop: '5px', margin: 0 }}>
                    {host.services.map((svc, i) => (
                      <li key={i} style={{ color: '#7f8c8d', fontSize: '14px', marginBottom: '4px' }}>
                        <span style={{ fontWeight: 'bold' }}>Port {svc.port}</span>: {svc.product} 
                        {svc.vuln_count > 0 ? (
                           <span style={{ color: '#e74c3c', marginLeft: '10px', fontWeight: 'bold' }}>⚠️ {svc.vuln_count} CVEs</span>
                        ) : (
                           <span style={{ color: '#27ae60', marginLeft: '10px' }}>✅ Safe</span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
};

const styles = {
  card: {
    background: 'white', padding: '25px', borderRadius: '10px',
    textAlign: 'center', boxShadow: '0 4px 10px rgba(0,0,0,0.05)',
    display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center'
  }
};

export default Dashboard;