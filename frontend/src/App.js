import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import History from './pages/History';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import API_BASE_URL from './config'; // <--- IMPORT THE CLOUD CONFIG
import './App.css';

function App() {
  // --- STATE ---
  const [token, setToken] = useState(localStorage.getItem('userToken'));
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [isRegistering, setIsRegistering] = useState(false);
  
  // Data State (Shared across pages)
  const [file, setFile] = useState(null);
  const [data, setData] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // --- EFFECT: Load History if Token Exists ---
  useEffect(() => {
    if (token) fetchHistory();
  }, [token]);

  // --- AUTH FUNCTIONS ---
  const handleAuth = async (e) => {
    e.preventDefault();
    const endpoint = isRegistering ? 'register/' : 'login/';
    const payload = { username, password };

    try {
      // UPDATED: Use API_BASE_URL
      const response = await axios.post(`${API_BASE_URL}/api/${endpoint}`, payload);
      const newToken = response.data.token;
      setToken(newToken);
      localStorage.setItem('userToken', newToken);
      setError(null);
    } catch (err) {
      setError(err.response?.data?.error || "Authentication failed");
    }
  };

  const handleLogout = () => {
    setToken(null);
    localStorage.removeItem('userToken');
    setData(null);
    setHistory([]);
  };

  // --- API FUNCTIONS ---
  const fetchHistory = async () => {
    try {
      // UPDATED: Use API_BASE_URL
      const response = await axios.get(`${API_BASE_URL}/api/upload-scan/`, {
        headers: { 'Authorization': `Token ${token}` }
      });
      setHistory(response.data);
    } catch (err) {
      console.error("Failed to load history", err);
    }
  };

  const handleUpload = async () => {
    if (!file) { setError("Please select a file first."); return; }
    const formData = new FormData();
    formData.append('file', file);
    setLoading(true);

    try {
      // UPDATED: Use API_BASE_URL
      const response = await axios.post(`${API_BASE_URL}/api/upload-scan/`, formData, {
        headers: { 'Content-Type': 'multipart/form-data', 'Authorization': `Token ${token}` },
      });
      setData(response.data);
      fetchHistory();
      setError(null);
    } catch (err) {
      console.error(err);
      setError("Upload failed.");
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (scanId, filename) => {
    try {
      // UPDATED: Use API_BASE_URL
      const response = await axios.get(`${API_BASE_URL}/api/report/${scanId}/`, {
        headers: { 'Authorization': `Token ${token}` },
        responseType: 'blob',
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `report_${filename}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      alert("Failed to download report.");
    }
  };

  // --- RENDER: LOGIN SCREEN ---
  if (!token) {
    return (
      <div style={{ height: "100vh", display: "flex", justifyContent: "center", alignItems: "center", background: "#ecf0f1", fontFamily: "Arial" }}>
        <div style={{ background: "white", padding: "40px", borderRadius: "10px", boxShadow: "0 4px 20px rgba(0,0,0,0.1)", width: "350px", textAlign: "center" }}>
          <h2 style={{ color: "#2c3e50" }}>🔒 ANSAS Login</h2>
          <form onSubmit={handleAuth}>
            <input type="text" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} style={{ width: "90%", padding: "10px", margin: "10px 0", borderRadius: "5px", border: "1px solid #ddd" }} />
            <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} style={{ width: "90%", padding: "10px", margin: "10px 0", borderRadius: "5px", border: "1px solid #ddd" }} />
            <button type="submit" style={{ width: "100%", padding: "12px", background: "#3498db", color: "white", border: "none", borderRadius: "5px", marginTop: "10px", fontWeight: "bold", cursor: "pointer" }}>{isRegistering ? "Create Account" : "Sign In"}</button>
          </form>
          <p style={{ marginTop: "20px", fontSize: "0.9em", color: "#7f8c8d", cursor: "pointer" }} onClick={() => setIsRegistering(!isRegistering)}>{isRegistering ? "Already have an account? Login" : "Need an account? Register"}</p>
          {error && <p style={{ color: "red", marginTop: "10px" }}>{error}</p>}
        </div>
      </div>
    );
  }

  // --- RENDER: MAIN APP (WITH SIDEBAR) ---
  return (
    <Router>
      <div style={{ display: 'flex' }}>
        {/* 1. SIDEBAR (Fixed Left) */}
        <Sidebar onLogout={handleLogout} />

        {/* 2. MAIN CONTENT (Right Side) */}
        <div style={{ marginLeft: '240px', width: '100%', padding: '0', backgroundColor: '#ecf0f1', minHeight: '100vh' }}>
          <Routes>
            <Route path="/" element={
              <Dashboard 
                file={file} 
                setFile={setFile} 
                handleUpload={handleUpload} 
                loading={loading} 
                error={error} 
                data={data} 
              />
            } />
            <Route path="/history" element={
              <History 
                history={history} 
                handleDownload={handleDownload} 
              />
            } />
            <Route path="/reports" element={
              <Reports 
                history={history} 
                handleDownload={handleDownload} 
              />
            } />
            <Route path="/settings" element={<Settings />} />
            
            {/* Redirect unknown routes to Dashboard */}
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </div>
      </div>
    </Router>
  );
}

export default App;