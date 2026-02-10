# 🛡️ ANSAS - Automated Network Security Assessment System

![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen)
![Platform](https://img.shields.io/badge/Platform-SaaS-blue)
![License](https://img.shields.io/badge/License-MIT-orange)

**ANSAS** is a full-stack SaaS platform designed to automate the analysis of network vulnerability scans. It ingests **Nmap XML** files, processes them through a secure cloud API, and visualizes critical security data in a real-time dashboard.

🔴 **Live Demo:** [https://ansas-security-platform.vercel.app](https://ansas-security-platform.vercel.app)

---

## 🚀 Key Features

* **📊 Interactive Dashboard:** Visualizes vulnerability severity (Critical vs. Low) and port distribution using dynamic charts.
* **⚡ Real-Time Parsing:** Instantly processes complex Nmap XML outputs into human-readable insights.
* **📂 Report Generation:** Auto-generates professional PDF security audit reports for clients.
* **☁️ Cloud-Native Architecture:** Fully deployed on serverless infrastructure (Vercel & Render).
* **🔒 Secure Storage:** Encrypted database connections using MongoDB Atlas.

---

## 📸 Screenshots

### 1. Security Operations Dashboard
*(Place your "Perfect Result" screenshot here. Name it `dashboard.png` and put it in a `screenshots` folder)*
![Dashboard Preview](./screenshots/dashboard.png)

---

## 🛠️ Tech Stack

### **Frontend (Client)**
* **Framework:** React.js (v18)
* **Visualization:** Recharts
* **Routing:** React Router DOM
* **Hosting:** Vercel

### **Backend (API)**
* **Framework:** Django REST Framework (DRF)
* **Language:** Python 3.12
* **Security:** CORS Headers, JWT Authentication
* **Hosting:** Render (Cloud)

### **Database**
* **Core:** MongoDB Atlas (NoSQL)
* **Connection:** Djongo Engine

---

## ⚙️ Architecture

```mermaid
graph TD
    User[Admin User] -->|HTTPS| Frontend[React Dashboard (Vercel)]
    Frontend -->|JSON API| Backend[Django API (Render)]
    Backend -->|Read/Write| DB[(MongoDB Atlas)]
    Backend -->|Generate| PDF[Audit Report]