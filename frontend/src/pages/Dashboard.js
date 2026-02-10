import React, { useState } from 'react';
import { 
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer, 
  BarChart, Bar, XAxis, YAxis, CartesianGrid 
} from 'recharts';
import { 
  Upload, Activity, AlertTriangle, Shield, Server, 
  FileText, CheckCircle, Loader, Search, Download 
} from 'lucide-react';

// Added 'handleDownload' back to the props list
const Dashboard = ({ file, setFile, handleUpload, handleDownload, loading, error, data }) => {
  const [isHovering, setIsHovering] = useState(false);

  // --- 1. DATA PROCESSING ---
  const getHosts = () => {
    if (!data) return [];
    if (Array.isArray(data)) return data;
    if (data.results && Array.isArray(data.results)) return data.results;
    if (data.scan_data && Array.isArray(data.scan_data)) return data.scan_data;
    return [];
  };

  const hosts = getHosts();

  const processCharts = () => {
    if (hosts.length === 0) return { pieData: [], barData: [], totalVulns: 0, criticalVulns: 0 };

    let critical = 0, high = 0, medium = 0, low = 0, total = 0;
    const portCounts = {};

    hosts.forEach(host => {
      if (host.services && Array.isArray(host.services)) {
        host.services.forEach(svc => {
          const port = svc.port;
          portCounts[port] = (portCounts[port] || 0) + 1;
          
          if (svc.vulnerabilities) {
            svc.vulnerabilities.forEach(v => {
              total++;
              if (v.cvss_score >= 9.0) critical++;
              else if (v.cvss_score >= 7.0) high++;
              else if (v.cvss_score >= 4.0) medium++;
              else low++;
            });
          }
        });
      }
    });

    const pieData = [
      { name: 'Critical', value: critical, color: '#ef4444' }, 
      { name: 'High', value: high, color: '#f97316' },     
      { name: 'Medium', value: medium, color: '#eab308' }, 
      { name: 'Low', value: low, color: '#22c55e' },      
    ].filter(i => i.value > 0);

    const barData = Object.keys(portCounts).map(port => ({
      name: `Port ${port}`,
      count: portCounts[port]
    })).sort((a, b) => b.count - a.count).slice(0, 5);

    return { pieData, barData, totalVulns, criticalVulns };
  };

  const { pieData, barData, totalVulns, criticalVulns } = processCharts();

  // --- 2. UI HELPERS ---
  const handleDragOver = (e) => { e.preventDefault(); setIsHovering(true); };
  const handleDragLeave = () => setIsHovering(false);
  const handleDrop = (e) => {
    e.preventDefault();
    setIsHovering(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  return (
    <div style={styles.container}>
      
      {/* HEADER SECTION */}
      <div style={styles.header}>
        <div>
          <h1 style={styles.title}>
            <Shield size={32} style={{ marginRight: 12, color: '#2563eb' }} />
            ANSAS <span style={{ fontWeight: 300, color: '#64748b' }}>Security Console</span>
          </h1>
          <p style={styles.subtitle}>Automated Network Security Assessment System</p>
        </div>
        
        {/* ACTION BUTTONS (PDF Download Restored) */}
        <div style={{ display: 'flex', gap: '10px' }}>
            {hosts.length > 0 && (
                <button onClick={handleDownload} style={styles.downloadBtn}>
                    <Download size={16} style={{ marginRight: 8 }} />
                    Export Report
                </button>
            )}
            <div style={styles.statusBadge}>
            <Activity size={16} style={{ marginRight: 6 }} />
            System Active
            </div>
        </div>
      </div>

      {/* UPLOAD SECTION */}
      <div style={styles.uploadSection}>
        {!loading ? (
          <div 
            style={{ 
              ...styles.dropZone, 
              borderColor: isHovering ? '#2563eb' : '#e2e8f0',
              backgroundColor: isHovering ? '#eff6ff' : '#f8fafc' 
            }}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
          >
            <input 
              type="file" 
              id="fileInput"
              accept=".xml" 
              onChange={(e) => setFile(e.target.files[0])} 
              style={{ display: 'none' }} 
            />
            
            <div style={{ textAlign: 'center' }}>
              {file ? (
                <div style={styles.fileSelected}>
                  <FileText size={48} color="#2563eb" />
                  <p style={styles.fileName}>{file.name}</p>
                  <button onClick={handleUpload} style={styles.analyzeBtn}>
                    <Search size={18} style={{ marginRight: 8 }} />
                    Run Security Audit
                  </button>
                  <p style={{marginTop: 10, fontSize: '0.8rem', color: '#64748b', cursor: 'pointer'}} onClick={() => setFile(null)}>Change File</p>
                </div>
              ) : (
                <label htmlFor="fileInput" style={{ cursor: 'pointer' }}>
                  <div style={styles.uploadIconWrapper}>
                    <Upload size={32} color="#64748b" />
                  </div>
                  <h3 style={styles.uploadTitle}>Upload Nmap Scan</h3>
                  <p style={styles.uploadText}>Drag & drop your XML file here, or click to browse</p>
                </label>
              )}
            </div>
          </div>
        ) : (
          <div style={styles.loadingState}>
            <Loader size={48} className="spin-animation" color="#2563eb" />
            <h3 style={{ marginTop: 20, color: '#1e293b' }}>Analyzing Network Topology...</h3>
            <p style={{ color: '#64748b' }}>Parsing vulnerabilities and mapping assets</p>
          </div>
        )}
        
        {error && (
          <div style={styles.errorBanner}>
            <AlertTriangle size={20} />
            <span style={{ marginLeft: 10 }}>{error}</span>
          </div>
        )}
      </div>

      {/* RESULTS DASHBOARD */}
      {hosts.length > 0 && (
        <div style={styles.dashboardGrid}>
          
          {/* KPI CARDS */}
          <div style={styles.statsRow}>
            <StatCard icon={Server} color="#3b82f6" label="Total Assets" value={hosts.length} />
            <StatCard icon={AlertTriangle} color="#ef4444" label="Critical Issues" value={criticalVulns} />
            <StatCard icon={Activity} color="#f59e0b" label="Total Vulns" value={totalVulns} />
            <StatCard icon={CheckCircle} color="#10b981" label="Secure Hosts" value={hosts.length - Math.min(hosts.length, criticalVulns)} />
          </div>

          {/* CHARTS ROW */}
          <div style={styles.chartContainer}>
            <div style={styles.chartCard}>
              <h3 style={styles.cardTitle}>Vulnerability Severity</h3>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie data={pieData} innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend verticalAlign="bottom" height={36}/>
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div style={styles.chartCard}>
              <h3 style={styles.cardTitle}>Top Risky Ports</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={barData} layout="vertical" margin={{ left: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                  <XAxis type="number" hide />
                  <YAxis dataKey="name" type="category" width={80} tick={{fontSize: 12}} />
                  <Tooltip cursor={{fill: '#f1f5f9'}} />
                  <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} barSize={20} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* ASSET LIST */}
          <div style={styles.tableCard}>
            <h3 style={styles.cardTitle}>Detailed Asset Intelligence</h3>
            <div style={styles.tableWrapper}>
              {hosts.map((host, idx) => (
                <div key={idx} style={styles.hostRow}>
                  <div style={styles.hostHeader}>
                    <div style={{ display: 'flex', alignItems: 'center' }}>
                      <div style={styles.ipBadge}>{host.ip_address}</div>
                      <span style={styles.osText}>{host.os_name || "Unknown OS"}</span>
                    </div>
                    <div style={styles.vulnCountBadge}>
                      {host.services ? host.services.length : 0} Services
                    </div>
                  </div>
                  
                  <div style={styles.serviceGrid}>
                    {host.services && host.services.map((svc, i) => (
                      <div key={i} style={styles.serviceTag}>
                        <span style={{fontWeight: 600, marginRight: 5}}>{svc.port}/{svc.protocol}</span>
                        <span style={{color: '#64748b'}}>{svc.product}</span>
                        {svc.vuln_count > 0 && <span style={styles.miniAlert}>⚠️ {svc.vuln_count}</span>}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>
      )}
      
      {/* CSS ANIMATION FOR LOADER */}
      <style>{`
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .spin-animation { animation: spin 2s linear infinite; }
      `}</style>
    </div>
  );
};

// --- SUB-COMPONENTS ---
const StatCard = ({ icon: Icon, color, label, value }) => (
  <div style={styles.statCard}>
    <div style={{ ...styles.iconBox, backgroundColor: `${color}20`, color: color }}>
      <Icon size={24} />
    </div>
    <div>
      <h4 style={styles.statValue}>{value}</h4>
      <p style={styles.statLabel}>{label}</p>
    </div>
  </div>
);

// --- STYLES OBJECT ---
const styles = {
  container: { maxWidth: '1200px', margin: '0 auto', padding: '40px 20px', fontFamily: "'Inter', sans-serif", color: '#1e293b' },
  header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '40px' },
  title: { fontSize: '1.8rem', fontWeight: '800', display: 'flex', alignItems: 'center', margin: 0, color: '#0f172a' },
  subtitle: { margin: '5px 0 0 45px', color: '#64748b', fontSize: '0.9rem' },
  statusBadge: { display: 'flex', alignItems: 'center', padding: '6px 12px', background: '#dcfce7', color: '#166534', borderRadius: '20px', fontSize: '0.85rem', fontWeight: '600' },
  downloadBtn: { display: 'flex', alignItems: 'center', padding: '8px 16px', background: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px', cursor: 'pointer', fontWeight: '600', color: '#475569' },
  
  uploadSection: { marginBottom: '50px' },
  dropZone: { border: '2px dashed #e2e8f0', borderRadius: '16px', padding: '60px', transition: 'all 0.2s ease', minHeight: '300px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' },
  uploadIconWrapper: { background: '#fff', padding: '20px', borderRadius: '50%', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)', marginBottom: '20px', display: 'inline-block' },
  uploadTitle: { fontSize: '1.25rem', fontWeight: '700', margin: '0 0 10px 0' },
  uploadText: { color: '#64748b', margin: 0 },
  fileSelected: { display: 'flex', flexDirection: 'column', alignItems: 'center' },
  fileName: { fontSize: '1.1rem', fontWeight: '600', margin: '15px 0' },
  analyzeBtn: { background: '#2563eb', color: 'white', border: 'none', padding: '12px 32px', borderRadius: '8px', fontSize: '1rem', fontWeight: '600', cursor: 'pointer', display: 'flex', alignItems: 'center', boxShadow: '0 4px 6px -1px rgba(37, 99, 235, 0.3)' },
  loadingState: { textAlign: 'center', padding: '40px' },
  errorBanner: { background: '#fee2e2', color: '#991b1b', padding: '16px', borderRadius: '8px', marginTop: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: '500' },

  dashboardGrid: { animation: 'fadeIn 0.5s ease-in' },
  statsRow: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px', marginBottom: '30px' },
  statCard: { background: 'white', padding: '24px', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', display: 'flex', alignItems: 'center', border: '1px solid #f1f5f9' },
  iconBox: { width: '48px', height: '48px', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', marginRight: '16px' },
  statValue: { fontSize: '1.5rem', fontWeight: '800', margin: 0, lineHeight: 1 },
  statLabel: { color: '#64748b', fontSize: '0.875rem', margin: '4px 0 0 0', fontWeight: '500' },

  chartContainer: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '24px', marginBottom: '30px' },
  chartCard: { background: 'white', padding: '24px', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', border: '1px solid #f1f5f9' },
  cardTitle: { fontSize: '1.1rem', fontWeight: '700', marginBottom: '20px', color: '#0f172a' },

  tableCard: { background: 'white', padding: '24px', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', border: '1px solid #f1f5f9' },
  tableWrapper: { maxHeight: '500px', overflowY: 'auto' },
  hostRow: { borderBottom: '1px solid #f1f5f9', padding: '16px 0' },
  hostHeader: { display: 'flex', justifyContent: 'space-between', marginBottom: '10px' },
  ipBadge: { fontFamily: 'monospace', background: '#f1f5f9', padding: '4px 8px', borderRadius: '4px', fontWeight: '700', color: '#334155', marginRight: '10px' },
  osText: { color: '#64748b', fontSize: '0.9rem' },
  vulnCountBadge: { fontSize: '0.8rem', fontWeight: '600', color: '#64748b' },
  serviceGrid: { display: 'flex', flexWrap: 'wrap', gap: '8px' },
  serviceTag: { fontSize: '0.8rem', background: '#f8fafc', border: '1px solid #e2e8f0', padding: '4px 8px', borderRadius: '4px', display: 'flex', alignItems: 'center' },
  miniAlert: { marginLeft: '6px', color: '#ef4444', fontSize: '0.75rem', fontWeight: 'bold' }
};

export default Dashboard;