import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import History from './pages/History';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import API_BASE_URL from './config';
import './App.css';

function App() {
  // --- AUTH STATE ---
  const [token, setToken] = useState(localStorage.getItem('userToken'));
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [isRegistering, setIsRegistering] = useState(false);
  
  // --- DATA STATE ---
  const [file, setFile] = useState(null);
  const [data, setData] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // --- API FUNCTIONS ---
  const fetchHistory = useCallback(async () => {
    if (!token) return;
    try {
      const response = await axios.get(`${API_BASE_URL}/api/upload-scan/`, {
        headers: { 'Authorization': `Token ${token}` }
      });
      setHistory(response.data);
    } catch (err) {
      console.error("Failed to load history", err);
      // If unauthorized, clear token
      if (err.response?.status === 401) {
        handleLogout();
      }
    }
  }, [token]);

  // --- EFFECT: Load History if Token Exists ---
  useEffect(() => {
    if (token) fetchHistory();
  }, [token, fetchHistory]);

  // --- AUTH FUNCTIONS ---
  const handleAuth = async (e) => {
    e.preventDefault();
    setError(null);
    const endpoint = isRegistering ? 'register/' : 'login/';
    const payload = { username, password };

    try {
      const response = await axios.post(`${API_BASE_URL}/api/${endpoint}`, payload);
      const newToken = response.data.token || response.data.access; 
      
      if (newToken) {
        setToken(newToken);
        localStorage.setItem('userToken', newToken);
      } else if (isRegistering) {
        setIsRegistering(false);
        alert("Registration successful! Please log in.");
      }
    } catch (err) {
      setError(err.response?.data?.error || "Authentication failed. Check credentials.");
    }
  };

  const handleLogout = () => {
    setToken(null);
    localStorage.removeItem('userToken');
    setData(null);
    setHistory([]);
    setFile(null);
  };

  // --- SCAN UPLOAD LOGIC ---
  const handleUpload = async () => {
    if (!file) { setError("Please select a file first."); return; }
    
    const formData = new FormData();
    formData.append('file', file);
    setLoading(true);
    setError(null);

    try {
      const response = await axios.post(`${API_BASE_URL}/api/upload-scan/`, formData, {
        headers: { 
          'Content-Type': 'multipart/form-data', 
          'Authorization': `Token ${token}` 
        },
      });
      // Store the response data (which includes db_id) in state
      setData(response.data);
      // Refresh sidebar history
      fetchHistory();
    } catch (err) {
      console.error("Upload Error:", err);
      setError("Upload failed. Please check the file format or server status.");
    } finally {
      setLoading(false);
    }
  };

  // --- DOWNLOAD LOGIC WITH WHITE LABEL SUPPORT ---
  const handleDownload = async (scanId, filename, config = {}) => {
    try {
      const params = new URLSearchParams();
      
      // Map config keys to Backend expected keys
      if (config.clientName) params.append('client_name', config.clientName);
      if (config.clientEmail) params.append('client_email', config.clientEmail);
      if (config.clientPhone) params.append('client_phone', config.clientPhone);
      if (config.auditorName) params.append('auditor_name', config.auditorName);

      const response = await axios.get(`${API_BASE_URL}/api/report/${scanId}/?${params.toString()}`, {
        headers: { 'Authorization': `Token ${token}` },
        responseType: 'blob',
      });

      // Create blob link and trigger download
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      
      // Dynamic Filename
      const safeClientName = config.clientName ? config.clientName.replace(/\s+/g, '_') : 'Scan';
      link.setAttribute('download', `ANSAS_Report_${safeClientName}.pdf`);
      
      document.body.appendChild(link);
      link.click();
      
      // Cleanup
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Download Error", err);
      alert("Failed to download report. The session may have expired or the report is missing.");
    }
  };

  // --- RENDER: LOGIN/REGISTER SCREEN ---
  if (!token) {
    return (
      <div style={{ height: "100vh", display: "flex", justifyContent: "center", alignItems: "center", background: "#f1f5f9", fontFamily: "'Inter', sans-serif" }}>
        <div style={{ background: "white", padding: "40px", borderRadius: "12px", boxShadow: "0 10px 25px -5px rgba(0,0,0,0.1)", width: "380px", textAlign: "center" }}>
          <h2 style={{ color: "#1e293b", marginBottom: "20px", fontWeight: '800' }}>🔒 ANSAS Console</h2>
          <form onSubmit={handleAuth}>
            <input type="text" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} required style={{ width: "100%", padding: "12px", margin: "10px 0", borderRadius: "8px", border: "1px solid #e2e8f0", boxSizing: "border-box" }} />
            <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required style={{ width: "100%", padding: "12px", margin: "10px 0", borderRadius: "8px", border: "1px solid #e2e8f0", boxSizing: "border-box" }} />
            <button type="submit" style={{ width: "100%", padding: "12px", background: "#2563eb", color: "white", border: "none", borderRadius: "8px", marginTop: "10px", fontWeight: "700", cursor: "pointer" }}>
                {isRegistering ? "Create Account" : "Sign In"}
            </button>
          </form>
          <p style={{ marginTop: "20px", fontSize: "0.85em", color: "#64748b", cursor: "pointer" }} onClick={() => setIsRegistering(!isRegistering)}>
            {isRegistering ? "Already have an account? Sign In" : "New user? Create an account"}
          </p>
          {error && <div style={{ color: "#b91c1c", marginTop: "15px", fontSize: "0.85rem", background: "#fef2f2", padding: "10px", borderRadius: "6px", border: "1px solid #fee2e2" }}>{error}</div>}
        </div>
      </div>
    );
  }

  // --- RENDER: MAIN DASHBOARD ---
  return (
    <Router>
      <div style={{ display: 'flex', minHeight: '100vh', backgroundColor: '#f8fafc' }}>
        <Sidebar onLogout={handleLogout} />
        
        <div style={{ marginLeft: '240px', width: 'calc(100% - 240px)', padding: '0' }}>
          <Routes>
            <Route 
                path="/" 
                element={
                    <Dashboard 
                        file={file} 
                        setFile={setFile} 
                        handleUpload={handleUpload} 
                        handleDownload={(config) => {
                            // Detect the ID from the last upload response
                            const scanId = data?.db_id || data?.id || data?._id;
                            
                            if (scanId) {
                                handleDownload(scanId, "current_scan", config);
                            } else {
                                alert("Please upload and analyze a scan first to generate a report.");
                            }
                        }}
                        loading={loading} 
                        error={error} 
                        data={data} 
                    />
                } 
            />
            <Route 
                path="/history" 
                element={<History history={history} handleDownload={handleDownload} />} 
            />
            <Route 
                path="/reports" 
                element={<Reports history={history} handleDownload={handleDownload} />} 
            />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </div>
      </div>
    </Router>
  );
}

export default App;