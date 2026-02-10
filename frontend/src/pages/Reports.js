import React from 'react';
import { FileText, Download } from 'lucide-react';

const Reports = ({ history, handleDownload }) => {
  return (
    <div style={{ padding: '30px', animation: 'fadeIn 0.5s' }}>
      <div style={{ marginBottom: '30px' }}>
        <h2 style={{ color: '#2c3e50', margin: 0 }}>📂 Generated Reports</h2>
        <p style={{ color: '#7f8c8d' }}>Access and share your security assessment documents.</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: '25px' }}>
        {history.map((scan, index) => (
          <div key={index} style={styles.reportCard}>
            <div style={styles.iconArea}>
              <FileText size={40} color="#e74c3c" /> 
              <span style={{ fontSize: '10px', background: '#e74c3c', color: 'white', padding: '2px 5px', borderRadius: '3px', position: 'absolute', bottom: '25px' }}>PDF</span>
            </div>
            
            <div style={{ padding: '20px', textAlign: 'center' }}>
              <h4 style={{ margin: '0 0 5px 0', color: '#2c3e50', fontSize: '16px' }}>{scan.filename}</h4>
              <p style={{ margin: '0 0 15px 0', color: '#95a5a6', fontSize: '12px' }}>Generated: {scan.upload_date}</p>
              
              <button 
                onClick={() => handleDownload(scan._id || scan.id, scan.filename)}
                style={styles.actionBtn}
              >
                <Download size={14} style={{ marginRight: '5px' }} /> Download
              </button>
            </div>
          </div>
        ))}

        {history.length === 0 && (
          <p style={{ color: '#7f8c8d' }}>No reports generated yet.</p>
        )}
      </div>
    </div>
  );
};

const styles = {
  reportCard: {
    background: 'white', borderRadius: '10px', overflow: 'hidden',
    boxShadow: '0 4px 15px rgba(0,0,0,0.05)', transition: 'transform 0.2s',
    border: '1px solid #f0f0f0'
  },
  iconArea: {
    background: '#fdf2f2', height: '100px', display: 'flex',
    alignItems: 'center', justifyContent: 'center', position: 'relative'
  },
  actionBtn: {
    background: '#2c3e50', color: 'white', border: 'none',
    padding: '10px 20px', borderRadius: '5px', cursor: 'pointer',
    width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center',
    fontSize: '13px', fontWeight: 'bold'
  }
};

export default Reports;