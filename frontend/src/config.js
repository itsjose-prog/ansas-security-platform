// Switches between Localhost and Cloud automatically
const API_BASE_URL = window.location.hostname === 'localhost' 
  ? 'http://127.0.0.1:8000'  // Development (Laptop)
  : 'https://ansas-backend.onrender.com'; // Production (Cloud)

export default API_BASE_URL;