# Sentinel-Core: Autonomous Cloud-Native SOC Analyst

A real-time cybersecurity simulation environment that emulates a modern Security Operations Center (SOC) with AI-powered threat detection and response capabilities.

![Sentinel-Core Dashboard](https://img.shields.io/badge/Status-Live-emerald) ![React](https://img.shields.io/badge/React-18-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-Python-green)

## 🎯 Overview

Sentinel-Core simulates a cloud-native SOC where analysts (or autonomous agents) monitor security alerts, investigate threats, and take defensive actions across a distributed infrastructure. The platform features realistic alert generation, host compromise modeling, and a reward-based scoring system.

## ✨ Features

### 🔐 Secure Login Portal
- **Multi-role authentication** (Analyst, Senior Analyst, SOC Lead, Admin)
- **MFA support** for privileged accounts
- **Beautiful glassmorphism UI** with animated backgrounds
- **Demo credentials** pre-filled for easy testing

### 📊 SOC Dashboard
1. **Alerts Panel**
   - Real-time alert table with ID, severity, type, confidence, status
   - Color-coded severity (Red=High, Yellow=Medium, Green=Low)
   - Filter by severity and type
   - Search functionality

2. **System Metrics**
   - Compromised hosts counter
   - Anomaly score (0-100%)
   - CPU usage monitoring
   - Threat level gauge
   - Host risk distribution chart

3. **Action Controls**
   - Investigate Alert
   - Block IP
   - Isolate Host
   - Ignore Alert
   - Escalate
   - Resolve
   - Keyboard shortcuts (B/I/S/R)

4. **Visualization**
   - System Health Timeline (Recharts)
   - CPU & Anomaly trends
   - Real-time updating charts
   - Dark SOC theme

5. **Activity Logs**
   - Timestamped action history
   - Reward tracking
   - Color-coded by severity

6. **Simulation Controls**
   - Reset Environment
   - Run Step
   - Auto-play mode (adjustable speed)
   - Score tracking (0-100%)

## 🏗️ Architecture

```
Frontend (React + Vite)          Backend (FastAPI)
     │                                 │
     ├─ Login Portal                   ├─ /login (JWT)
     ├─ Dashboard                      ├─ /reset
     ├─ Alerts Table                   ├─ /step
     ├─ Metrics & Charts               ├─ /state
     └─ Activity Feed                  └─ /health
```

## 🚀 Quick Start

### Frontend Only (Demo Mode)

The app works immediately with a built-in simulation engine:

```bash
npm install
npm run dev
```

Visit `http://localhost:5173`

**Login with:**
- Username: `analyst`
- Password: `soc2024`
- MFA: (leave blank for analyst)

### With Backend

1. **Start Backend:**
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

2. **Start Frontend:**
```bash
npm install
VITE_API_URL=http://localhost:8000 npm run dev
```

## 🔑 Demo Accounts

| Role | Username | Password | MFA Required |
|------|----------|----------|--------------|
| Analyst | `analyst` | `soc2024` | No |
| Senior Analyst | `senior` | `soc2024` | Yes (123456) |
| SOC Lead | `lead` | `soc2024` | Yes (123456) |
| Admin | `admin` | `sentinel` | Yes (123456) |

## 📡 API Endpoints

### Authentication
```http
POST /login
Content-Type: application/json

{
  "username": "analyst",
  "password": "soc2024",
  "mfa_code": "123456"
}
```

### Simulation
```http
GET  /state          # Get current state
POST /reset          # Reset environment
POST /step           # Take action

{
  "kind": "block_ip",
  "alertId": "A-1001"
}
```

### Response Example
```json
{
  "state": {
    "step": 5,
    "score": 0.78,
    "alerts": [...],
    "hosts": [...],
    "metrics": {
      "compromisedHosts": 1,
      "anomalyScore": 0.42,
      "cpu": 0.35,
      "threatLevel": 0.51
    }
  },
  "reward": 0.12,
  "done": false,
  "info": "IP blocked."
}
```

## 🐳 Docker Deployment

### Backend
```bash
cd backend
docker build -t sentinel-core-api .
docker run -p 8000:8000 sentinel-core-api
```

### Frontend
```bash
npm run build
# Deploy dist/ to Vercel, Netlify, or any static host
```

## ☁️ Production Deployment

### Backend → Hugging Face Spaces
1. Create new Space (Docker)
2. Upload `backend/` files
3. Space auto-deploys to `https://yourname-space.hf.space`

### Frontend → Vercel
1. Push to GitHub
2. Import to Vercel
3. Set env: `VITE_API_URL=https://your-backend.hf.space`
4. Deploy

## 🎮 How to Use

1. **Login** with demo credentials
2. **Review Alerts** in the left panel
3. **Select an alert** from dropdown
4. **Take action**:
   - `Investigate` → gathers more intel (+confidence)
   - `Block IP` → stops attacker (best for high severity)
   - `Isolate Host` → contains compromise (resets host risk)
   - `Ignore` → dismiss (penalty if high severity!)
   - `Escalate` → Tier-2 review
5. **Watch metrics** update in real-time
6. **Enable Auto-play** to watch AI agent
7. **Track score** - aim for 70%+

## 🧠 Simulation Details

The Sentinel-Core engine simulates:
- **12 cloud hosts** with dynamic risk scores
- **7 alert types**: PortScan, BruteForce, Phishing, Malware, Lateral, Exfiltration, Ransomware
- **Host compromise** when risk > 85%
- **Environmental drift** - new alerts spawn randomly
- **Reward system**:
  - Block high-severity: +0.12
  - Isolate host: +0.15
  - Ignore high-severity: -0.15
  - Successful investigation: +0.05

## 🛠️ Tech Stack

**Frontend:**
- React 18 with TypeScript
- Vite
- Tailwind CSS
- Recharts for visualization
- Local storage for session

**Backend:**
- FastAPI (Python 3.11)
- JWT authentication
- Pydantic models
- In-memory state (use Redis for production)

## 📁 Project Structure

```
sentinel-core/
├── src/
│   ├── App.tsx          # Main app with login + dashboard
│   ├── main.tsx
│   └── index.css
├── backend/
│   ├── main.py          # FastAPI server
│   ├── requirements.txt
│   ├── Dockerfile
│   └── README.md
├── public/
└── package.json
```

## 🔒 Security Notes

This is a **simulation** for training/demos:
- Demo passwords are hardcoded (change in production!)
- JWT secret should be in env var
- Use HTTPS in production
- Add rate limiting
- Persist state to database
- Enable CORS properly

## 🎨 UI Highlights

- Dark SOC theme (#030508 background)
- Glassmorphism cards
- Animated gradient orbs
- Real-time charts
- Color-coded severity pills
- Keyboard shortcuts
- Responsive grid layout
- Smooth transitions

## 📊 Metrics Explained

- **Score**: Overall SOC performance (0-100%)
- **Anomaly Score**: Unusual activity level
- **Threat Level**: Combined risk from active threats
- **Compromised Hosts**: Currently breached systems
- **Confidence**: ML model certainty (55-95%)

## 🤝 Contributing

This is a hackathon/demo project. To extend:
1. Add new alert types in backend
2. Implement real threat intel feeds
3. Connect to actual SIEM (Splunk, Sentinel)
4. Add playbook automation
5. Multi-tenant support

## 📄 License

MIT - Use for education and demos

---

**Built for cybersecurity training and SOC simulation. Not for production security monitoring without hardening.**