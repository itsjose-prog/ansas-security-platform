import React, { useState } from 'react';
import { 
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer, 
  BarChart, Bar, XAxis, YAxis, CartesianGrid 
} from 'recharts';
import { 
  Upload, Activity, AlertTriangle, Shield, Server, 
  FileText, CheckCircle, Loader, Search, Download, Settings, User, Briefcase, Mail, Phone, Share2
} from 'lucide-react';

const Dashboard = ({ file, setFile, handleUpload, handleDownload, loading, error, data }) => {
  const [isHovering, setIsHovering] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  
  // --- 1. White-Label State (INTACT) ---
  const [reportConfig, setReportConfig] = useState({
    clientName: '',
    clientEmail: '',
    clientPhone: '',
    auditorName: ''
  });

  // --- 2. Data Normalization (INTACT) ---
  const getHosts = () => {
    if (!data) return [];
    if (Array.isArray(data)) return data;
    if (data.scan_data && Array.isArray(data.scan_data)) return data.scan_data;
    if (data.results && Array.isArray(data.results)) return data.results;
    return [];
  };

  const hosts = getHosts();

  // --- 3. Compliance Data (INTACT) ---
  const compliance = data?.compliance_summary || data?.compliance_findings || null;

  // --- 4. Topology Data (INTACT) ---
  const topology = data?.topology || null;

  // --- 5. Chart Data Processing (INTACT) ---
  const processCharts = () => {
    if (hosts.length === 0) return { pieData: [], barData: [], totalVulns: 0, criticalVulns: 0 };

    let critical = 0, high = 0, medium = 0, low = 0, total = 0;
    const portCounts = {};

    hosts.forEach(host => {
      if (host.services && Array.isArray(host.services)) {
        host.services.forEach(svc => {
          const port = svc.port;
          if (port) portCounts[port] = (portCounts[port] || 0) + 1;
          
          if (svc.vulnerabilities) {
            svc.vulnerabilities.forEach(v => {
              total++;
              const score = parseFloat(v.cvss_score) || 0;
              if (score >= 9.0) critical++;
              else if (score >= 7.0) high++;
              else if (score >= 4.0) medium++;
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

    const barData = Object.keys(portCounts)
      .map(port => ({ name: `Port ${port}`, count: portCounts[port] }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    return { pieData, barData, totalVulns: total, criticalVulns: critical };
  };

  const { pieData, barData, totalVulns, criticalVulns } = processCharts();

  // --- 6. Event Handlers (INTACT) ---
  const handleDragOver = (e) => { e.preventDefault(); setIsHovering(true); };
  const handleDragLeave = () => setIsHovering(false);
  const handleDrop = (e) => {
    e.preventDefault();
    setIsHovering(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const onDownloadClick = () => {
    handleDownload(reportConfig);
  };

  return (
    <div style={styles.container}>
      {/* HEADER SECTION (INTACT) */}
      <div style={styles.header}>
        <div>
          <h1 style={styles.title}>
            <Shield size={32} style={{ marginRight: 12, color: '#2563eb' }} />
            ANSAS <span style={{ fontWeight: 300, color: '#64748b' }}>Security Console</span>
          </h1>
          <p style={styles.subtitle}>Automated Network Security Assessment System</p>
        </div>
        
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
            <button 
              onClick={() => setShowSettings(!showSettings)} 
              style={{...styles.iconBtn, backgroundColor: showSettings ? '#e2e8f0' : 'transparent'}}
              title="Report Settings"
            >
              <Settings size={20} color="#64748b" />
            </button>

            {hosts.length > 0 && (
                <button onClick={onDownloadClick} style={styles.downloadBtn}>
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

      {/* WHITE-LABEL SETTINGS PANEL (INTACT) */}
      {showSettings && (
        <div style={styles.configPanel}>
          <h3 style={styles.configTitle}>Report Customization (White Label)</h3>
          <div style={styles.configGrid}>
            <div style={styles.inputGroup}>
              <label style={styles.label}><User size={14} style={{marginRight: 5}}/> Client Name</label>
              <input 
                type="text" 
                placeholder="e.g. Acme Corp" 
                style={styles.input}
                value={reportConfig.clientName}
                onChange={(e) => setReportConfig({...reportConfig, clientName: e.target.value})}
              />
            </div>
            <div style={styles.inputGroup}>
              <label style={styles.label}><Briefcase size={14} style={{marginRight: 5}}/> Auditor / Company</label>
              <input 
                type="text" 
                placeholder="e.g. Ombati Josephat" 
                style={styles.input}
                value={reportConfig.auditorName}
                onChange={(e) => setReportConfig({...reportConfig, auditorName: e.target.value})}
              />
            </div>
            <div style={styles.inputGroup}>
              <label style={styles.label}><Mail size={14} style={{marginRight: 5}}/> Client Email</label>
              <input 
                type="email" 
                placeholder="client@example.com" 
                style={styles.input}
                value={reportConfig.clientEmail}
                onChange={(e) => setReportConfig({...reportConfig, clientEmail: e.target.value})}
              />
            </div>
            <div style={styles.inputGroup}>
              <label style={styles.label}><Phone size={14} style={{marginRight: 5}}/> Client Phone</label>
              <input 
                type="text" 
                placeholder="+254..." 
                style={styles.input}
                value={reportConfig.clientPhone}
                onChange={(e) => setReportConfig({...reportConfig, clientPhone: e.target.value})}
              />
            </div>
          </div>
        </div>
      )}

      {/* COMPLIANCE STATUS BANNER (INTACT) */}
      {compliance && (
        <div style={{
          ...styles.tableCard, 
          borderLeft: `6px solid ${compliance.status === 'Compliant' ? '#22c55e' : '#ef4444'}`,
          background: compliance.status === 'Compliant' ? '#f0fdf4' : '#fef2f2',
          marginBottom: '30px',
          animation: 'fadeIn 0.5s ease-out'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h3 style={{ ...styles.cardTitle, color: compliance.status === 'Compliant' ? '#166534' : '#991b1b', marginBottom: '5px' }}>
                Kenya DPA 2019 Compliance Status
              </h3>
              <p style={{ color: '#64748b', fontSize: '0.9rem', margin: 0 }}>
                Regulatory audit based on detected vulnerabilities and data encryption standards.
              </p>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ 
                fontSize: '1.5rem', 
                fontWeight: '900', 
                color: compliance.status === 'Compliant' ? '#16a34a' : '#dc2626' 
              }}>
                {compliance.status}
              </div>
              <div style={{ fontSize: '0.8rem', fontWeight: 'bold', color: '#64748b' }}>
                RISK LEVEL: {compliance.risk_level || 'UNKNOWN'}
              </div>
            </div>
          </div>

          {compliance.violations && compliance.violations.length > 0 && (
            <div style={{ marginTop: '15px', borderTop: '1px solid #e2e8f0', paddingTop: '10px' }}>
              <p style={{ fontSize: '0.85rem', fontWeight: '700', color: '#475569' }}>Primary Violations:</p>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', marginTop: '5px' }}>
                {compliance.violations.slice(0, 3).map((v, i) => (
                  <div key={i} style={{ background: '#fff', padding: '5px 10px', borderRadius: '4px', fontSize: '0.75rem', border: '1px solid #e2e8f0', color: '#1e293b' }}>
                    <strong>{v.section}:</strong> {v.provision}
                  </div>
                ))}
                {compliance.violations.length > 3 && (
                  <div style={{ fontSize: '0.75rem', color: '#64748b', alignSelf: 'center' }}>
                    + {compliance.violations.length - 3} more in PDF report
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TOPOLOGY MAP COMPONENT (ALIGNED & CENTERED) */}
      {topology && hosts.length > 0 && (
        <div style={{...styles.tableCard, marginBottom: '30px'}}>
           <h3 style={styles.cardTitle}>
             <Share2 size={18} style={{ marginRight: 10, color: '#2563eb' }} />
             Infrastructure Topology Map
           </h3>
           <div style={styles.topologyContainer}>
              {/* Central Scanner Node */}
              <div style={styles.scannerNode}>
                <Shield size={24} color="white" />
                <span style={styles.nodeLabel}>ANSAS Node</span>
              </div>

              {/* Orbiting Asset Nodes */}
              {topology.nodes.filter(n => n.id !== "Scanner").map((node, i) => {
                const angle = (i / (topology.nodes.length - 1)) * 2 * Math.PI;
                const radius = 120; // Distance from center
                const x = Math.cos(angle) * radius;
                const y = Math.sin(angle) * radius;
                
                return (
                  <div key={node.id} style={{ 
                    ...styles.assetNodeWrapper,
                    transform: `translate(${x}px, ${y}px)`
                  }}>
                    <div style={{ 
                      ...styles.assetNode,
                      borderColor: node.vulns > 0 ? '#ef4444' : '#22c55e',
                      background: node.vulns > 0 ? '#fee2e2' : '#dcfce7'
                    }}>
                      <Server size={20} color={node.vulns > 0 ? '#ef4444' : '#22c55e'} />
                    </div>
                    <span style={styles.assetNodeLabel}>{node.id}</span>
                  </div>
                );
              })}
           </div>
        </div>
      )}

      {/* UPLOAD SECTION (INTACT) */}
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
                  <p style={styles.changeFileLink} onClick={() => setFile(null)}>Change File</p>
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

      {/* RESULTS DASHBOARD (INTACT) */}
      {hosts.length > 0 && (
        <div style={styles.dashboardGrid}>
          <div style={styles.statsRow}>
            <StatCard icon={Server} color="#3b82f6" label="Total Assets" value={hosts.length} />
            <StatCard icon={AlertTriangle} color="#ef4444" label="Critical Issues" value={criticalVulns} />
            <StatCard icon={Activity} color="#f59e0b" label="Total Vulns" value={totalVulns} />
            <StatCard icon={CheckCircle} color="#10b981" label="Secure Hosts" value={hosts.length - Math.min(hosts.length, criticalVulns)} />
          </div>

          <div style={styles.chartContainer}>
            <div style={styles.chartCard}>
              <h3 style={styles.cardTitle}>Vulnerability Severity</h3>
              <div style={{ height: '300px', position: 'relative' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={pieData} innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                      {pieData.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} />)}
                    </Pie>
                    <Tooltip />
                    <Legend verticalAlign="bottom" height={36}/>
                  </PieChart>
                </ResponsiveContainer>
                <div style={styles.pieCenterText}>
                  <div style={styles.pieTotalValue}>{totalVulns}</div>
                  <div style={styles.pieTotalLabel}>Total Issues</div>
                </div>
              </div>
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
                    <div style={styles.vulnCountBadge}>{host.services ? host.services.length : 0} Services</div>
                  </div>
                  <div style={styles.serviceGrid}>
                    {host.services && host.services.map((svc, i) => (
                      <div key={i} style={styles.serviceTag}>
                        <div style={{ display: 'flex', flexDirection: 'column' }}>
                          <div style={{ display: 'flex', alignItems: 'center' }}>
                            <span style={{fontWeight: 600, marginRight: 5}}>{svc.port}/{svc.protocol}</span>
                            <span style={{color: '#64748b'}}>{svc.product}</span>
                            {svc.vuln_count > 0 && <span style={styles.miniAlert}>⚠️ {svc.vuln_count}</span>}
                          </div>
                          
                          {/* Remediation Display (INTACT) */}
                          {svc.remediation && svc.vuln_count > 0 && (
                            <div style={styles.remediationText}>
                              <strong>Fix:</strong> {svc.remediation.action}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
      <style>{`
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } } 
        .spin-animation { animation: spin 2s linear infinite; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
      `}</style>
    </div>
  );
};

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

const styles = {
  container: { maxWidth: '1200px', margin: '0 auto', padding: '40px 20px', fontFamily: "'Inter', sans-serif", color: '#1e293b' },
  header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '40px' },
  title: { fontSize: '1.8rem', fontWeight: '800', display: 'flex', alignItems: 'center', margin: 0, color: '#0f172a' },
  subtitle: { margin: '5px 0 0 45px', color: '#64748b', fontSize: '0.9rem' },
  statusBadge: { display: 'flex', alignItems: 'center', padding: '6px 12px', background: '#dcfce7', color: '#166534', borderRadius: '20px', fontSize: '0.85rem', fontWeight: '600' },
  downloadBtn: { display: 'flex', alignItems: 'center', padding: '8px 16px', background: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px', cursor: 'pointer', fontWeight: '600', color: '#475569', boxShadow: '0 1px 2px rgba(0,0,0,0.05)' },
  iconBtn: { border: 'none', padding: '8px', borderRadius: '8px', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'background-color 0.2s' },
  configPanel: { background: '#f8fafc', padding: '24px', borderRadius: '12px', border: '1px solid #e2e8f0', marginBottom: '30px', animation: 'fadeIn 0.3s ease-out' },
  configTitle: { fontSize: '1rem', fontWeight: '700', marginBottom: '15px', color: '#334155' },
  configGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px' },
  inputGroup: { display: 'flex', flexDirection: 'column' },
  label: { fontSize: '0.85rem', fontWeight: '600', marginBottom: '5px', color: '#64748b', display: 'flex', alignItems: 'center' },
  input: { padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1', fontSize: '0.95rem', transition: 'border-color 0.2s' },
  uploadSection: { marginBottom: '50px' },
  dropZone: { border: '2px dashed #e2e8f0', borderRadius: '16px', padding: '60px', transition: 'all 0.2s ease', minHeight: '300px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' },
  uploadIconWrapper: { background: '#fff', padding: '20px', borderRadius: '50%', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)', marginBottom: '20px', display: 'inline-block' },
  uploadTitle: { fontSize: '1.25rem', fontWeight: '700', margin: '0 0 10px 0' },
  uploadText: { color: '#64748b', margin: 0 },
  fileSelected: { display: 'flex', flexDirection: 'column', alignItems: 'center' },
  fileName: { fontSize: '1.1rem', fontWeight: '600', margin: '15px 0' },
  analyzeBtn: { background: '#2563eb', color: 'white', border: 'none', padding: '12px 32px', borderRadius: '8px', fontSize: '1rem', fontWeight: '600', cursor: 'pointer', display: 'flex', alignItems: 'center', boxShadow: '0 4px 6px -1px rgba(37, 99, 235, 0.3)' },
  changeFileLink: { marginTop: 10, fontSize: '0.8rem', color: '#64748b', cursor: 'pointer', textDecoration: 'underline' },
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
  pieCenterText: { position: 'absolute', top: '42%', left: '50%', transform: 'translate(-50%, -50%)', textAlign: 'center' },
  pieTotalValue: { fontSize: '2rem', fontWeight: '800', color: '#0f172a' },
  pieTotalLabel: { fontSize: '0.8rem', color: '#64748b', fontWeight: '600' },
  tableCard: { background: 'white', padding: '24px', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', border: '1px solid #f1f5f9' },
  tableWrapper: { maxHeight: '500px', overflowY: 'auto' },
  hostRow: { borderBottom: '1px solid #f1f5f9', padding: '16px 0' },
  hostHeader: { display: 'flex', justifyContent: 'space-between', marginBottom: '10px' },
  ipBadge: { fontFamily: 'monospace', background: '#f1f5f9', padding: '4px 8px', borderRadius: '4px', fontWeight: '700', color: '#334155', marginRight: '10px' },
  osText: { color: '#64748b', fontSize: '0.9rem' },
  vulnCountBadge: { fontSize: '0.8rem', fontWeight: '600', color: '#64748b' },
  serviceGrid: { display: 'flex', flexWrap: 'wrap', gap: '8px' },
  serviceTag: { fontSize: '0.8rem', background: '#f8fafc', border: '1px solid #e2e8f0', padding: '8px 12px', borderRadius: '4px', display: 'flex', alignItems: 'center' },
  remediationText: { fontSize: '0.75rem', color: '#16a34a', marginTop: '4px', borderTop: '1px solid #dcfce7', paddingTop: '4px' },
  miniAlert: { marginLeft: '6px', color: '#ef4444', fontSize: '0.75rem', fontWeight: 'bold' },

  // --- TOPOLOGY ALIGNMENT FIX APPLIED ---
  topologyContainer: {
    height: '350px',
    background: '#f8fafc',
    borderRadius: '12px',
    display: 'flex',          // Enables Flexbox
    alignItems: 'center',      // Vertical Centering
    justifyContent: 'center',   // Horizontal Centering
    position: 'relative',
    overflow: 'hidden',
    border: '1px solid #e2e8f0'
  },
  scannerNode: {
    width: '64px',
    height: '64px',
    borderRadius: '50%',
    background: '#2563eb',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 2,
    boxShadow: '0 0 20px rgba(37, 99, 235, 0.4)'
  },
  nodeLabel: {
    fontSize: '0.65rem',
    color: 'white',
    fontWeight: '700',
    marginTop: '4px'
  },
  assetNodeWrapper: {
    position: 'absolute',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    transition: 'all 0.5s ease'
  },
  assetNode: {
    width: '44px',
    height: '44px',
    borderRadius: '10px',
    border: '2px solid',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
  },
  assetNodeLabel: {
    fontSize: '0.7rem',
    fontWeight: '700',
    marginTop: '6px',
    color: '#334155',
    background: 'white',
    padding: '2px 6px',
    borderRadius: '4px',
    boxShadow: '0 1px 2px rgba(0,0,0,0.05)'
  }
};

export default Dashboard;