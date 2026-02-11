import React, { useState, useEffect, useCallback } from 'react'; // Added useCallback
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
  // --- STATE ---
  const [token, setToken] = useState(localStorage.getItem('userToken'));
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [isRegistering, setIsRegistering] = useState(false);
  
  // Data State
  const [file, setFile] = useState(null);
  const [data, setData] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // --- API FUNCTIONS ---
  const fetchHistory = useCallback(async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/upload-scan/`, {
        headers: { 'Authorization': `Token ${token}` }
      });
      setHistory(response.data);
    } catch (err) {
      console.error("Failed to load history", err);
    }
  }, [token]);

  // --- EFFECT: Load History if Token Exists ---
  useEffect(() => {
    if (token) fetchHistory();
  }, [token, fetchHistory]);

  // --- AUTH FUNCTIONS ---
  const handleAuth = async (e) => {
    e.preventDefault();
    setError(null); // Clear previous errors
    const endpoint = isRegistering ? 'register/' : 'login/';
    const payload = { username, password };

    try {
      const response = await axios.post(`${API_BASE_URL}/api/${endpoint}`, payload);
      // Handle different response structures (Login vs Register)
      const newToken = response.data.token || response.data.access; 
      
      if (newToken) {
        setToken(newToken);
        localStorage.setItem('userToken', newToken);
      } else {
        // If registering and no token returned immediately, switch to login
        if (isRegistering) {
            setIsRegistering(false);
            alert("Registration successful! Please log in.");
        }
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

  const handleUpload = async () => {
    if (!file) { setError("Please select a file first."); return; }
    
    const formData = new FormData();
    formData.append('file', file);
    setLoading(true);
    setError(null);

    try {
      const response = await axios.post(`${API_BASE_URL}/api/upload-scan/`, formData, {
        headers: { 'Content-Type': 'multipart/form-data', 'Authorization': `Token ${token}` },
      });
      setData(response.data); // This usually contains the new ID
      fetchHistory(); // Refresh the sidebar list
    } catch (err) {
      console.error(err);
      setError("Upload failed. Please check the file format.");
    } finally {
      setLoading(false);
    }
  };

  // --- UPDATED: Handle Download with White Label Support ---
  const handleDownload = async (scanId, filename, config = {}) => {
    try {
      // We send the config (clientName, auditorName) as Query Parameters
      const params = new URLSearchParams();
      if (config.clientName) params.append('client_name', config.clientName);
      if (config.auditorName) params.append('auditor_name', config.auditorName);

      const response = await axios.get(`${API_BASE_URL}/api/report/${scanId}/?${params.toString()}`, {
        headers: { 'Authorization': `Token ${token}` },
        responseType: 'blob', // Important for files
      });

      // Create a fake link to trigger the download
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      // Use client name in filename if available
      const downloadName = config.clientName 
        ? `Security_Audit_${config.clientName.replace(/\s+/g, '_')}.pdf`
        : `report_${filename}.pdf`;
        
      link.setAttribute('download', downloadName);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      console.error("Download Error", err);
      alert("Failed to download report. Please try again.");
    }
  };

  // --- RENDER: LOGIN SCREEN ---
  if (!token) {
    return (
      <div style={{ height: "100vh", display: "flex", justifyContent: "center", alignItems: "center", background: "#ecf0f1", fontFamily: "'Inter', sans-serif" }}>
        <div style={{ background: "white", padding: "40px", borderRadius: "12px", boxShadow: "0 4px 20px rgba(0,0,0,0.1)", width: "350px", textAlign: "center" }}>
          <h2 style={{ color: "#2c3e50", marginBottom: "20px" }}>🔒 ANSAS Login</h2>
          <form onSubmit={handleAuth}>
            <input 
                type="text" 
                placeholder="Username" 
                value={username} 
                onChange={(e) => setUsername(e.target.value)} 
                style={{ width: "100%", padding: "12px", margin: "10px 0", borderRadius: "6px", border: "1px solid #cbd5e1", boxSizing: "border-box" }} 
            />
            <input 
                type="password" 
                placeholder="Password" 
                value={password} 
                onChange={(e) => setPassword(e.target.value)} 
                style={{ width: "100%", padding: "12px", margin: "10px 0", borderRadius: "6px", border: "1px solid #cbd5e1", boxSizing: "border-box" }} 
            />
            <button type="submit" style={{ width: "100%", padding: "12px", background: "#2563eb", color: "white", border: "none", borderRadius: "6px", marginTop: "10px", fontWeight: "bold", cursor: "pointer", transition: "0.2s" }}>
                {isRegistering ? "Create Account" : "Sign In"}
            </button>
          </form>
          <p style={{ marginTop: "20px", fontSize: "0.9em", color: "#64748b", cursor: "pointer" }} onClick={() => setIsRegistering(!isRegistering)}>
            {isRegistering ? "Already have an account? Login" : "Need an account? Register"}
          </p>
          {error && <div style={{ color: "#ef4444", marginTop: "15px", fontSize: "0.9rem", background: "#fee2e2", padding: "8px", borderRadius: "4px" }}>{error}</div>}
        </div>
      </div>
    );
  }

  // --- RENDER: MAIN APP ---
  return (
    <Router>
      <div style={{ display: 'flex' }}>
        <Sidebar onLogout={handleLogout} />
        <div style={{ marginLeft: '240px', width: '100%', padding: '0', backgroundColor: '#f8fafc', minHeight: '100vh' }}>
          <Routes>
            <Route 
                path="/" 
                element={
                    <Dashboard 
                        file={file} 
                        setFile={setFile} 
                        handleUpload={handleUpload} 
                        // IMPORTANT: We pass a wrapper function here to link the Dashboard config to the App logic
                        handleDownload={(config) => {
                            if (data && data.id) {
                                handleDownload(data.id, "current_scan", config);
                            } else {
                                alert("No scan data available to download. Please upload a file first.");
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