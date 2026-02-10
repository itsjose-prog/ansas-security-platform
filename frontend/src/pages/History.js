import React from 'react';
import { FileText, Download, Calendar, HardDrive } from 'lucide-react';

const History = ({ history, handleDownload }) => {
  return (
    <div style={{ padding: '30px', animation: 'fadeIn 0.5s' }}>
      <div style={{ marginBottom: '30px' }}>
        <h2 style={{ color: '#2c3e50', margin: 0 }}>📜 Scan Audit Logs</h2>
        <p style={{ color: '#7f8c8d' }}>Historical record of all security assessments.</p>
      </div>

      <div style={{ marginTop: '20px' }}>
        {history.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '50px', background: 'white', borderRadius: '10px' }}>
            <FileText size={48} color="#bdc3c7" />
            <p style={{ color: '#7f8c8d', marginTop: '15px' }}>No scan history found. Run your first scan on the Dashboard.</p>
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', background: 'white', borderRadius: '10px', overflow: 'hidden', boxShadow: '0 4px 15px rgba(0,0,0,0.05)' }}>
            <thead style={{ background: '#34495e', color: 'white' }}>
              <tr>
                <th style={styles.th}>Scan Date</th>
                <th style={styles.th}>Target Filename</th>
                <th style={styles.th}>Assets Scanned</th>
                <th style={styles.th}>Status</th>
                <th style={styles.th}>Report</th>
              </tr>
            </thead>
            <tbody>
              {history.map((scan, index) => (
                <tr key={index} style={{ borderBottom: '1px solid #ecf0f1', transition: 'background 0.2s' }}>
                  <td style={styles.td}>
                    <div style={{ display: 'flex', alignItems: 'center' }}>
                      <Calendar size={14} style={{ marginRight: '8px', color: '#7f8c8d' }} />
                      {scan.upload_date || "Just now"}
                    </div>
                  </td>
                  <td style={styles.td}>
                    <div style={{ display: 'flex', alignItems: 'center', fontWeight: 'bold', color: '#2c3e50' }}>
                      <FileText size={16} style={{ marginRight: '8px', color: '#3498db' }} />
                      {scan.filename}
                    </div>
                  </td>
                  <td style={styles.td}>
                     <div style={{ display: 'flex', alignItems: 'center' }}>
                      <HardDrive size={14} style={{ marginRight: '8px', color: '#7f8c8d' }} />
                      {scan.asset_count}
                    </div>
                  </td>
                  <td style={styles.td}>
                    <span style={{ background: '#e8f8f5', color: '#27ae60', padding: '5px 12px', borderRadius: '15px', fontSize: '12px', fontWeight: 'bold', border: '1px solid #a3e4d7' }}>
                      Completed
                    </span>
                  </td>
                  <td style={styles.td}>
                    <button 
                      onClick={() => handleDownload(scan._id || scan.id, scan.filename)}
                      style={styles.downloadBtn}
                      title="Download PDF Report"
                    >
                      <Download size={14} style={{ marginRight: '6px' }} /> Download PDF
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

const styles = {
  th: { padding: '18px', textAlign: 'left', fontWeight: '600', fontSize: '14px', textTransform: 'uppercase', letterSpacing: '0.5px' },
  td: { padding: '18px', color: '#34495e', fontSize: '14px' },
  downloadBtn: {
    display: 'flex', alignItems: 'center', background: 'white',
    border: '1px solid #3498db', color: '#3498db',
    padding: '8px 15px', borderRadius: '5px', cursor: 'pointer',
    fontSize: '13px', fontWeight: '600', transition: '0.2s'
  }
};

export default History;