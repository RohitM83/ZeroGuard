# ZeroGuard
### AI-Based Zero-Day Attack Detection Using Graph Neural Networks

ZeroGuard is an academic cybersecurity project exploring AI-assisted network threat detection using Graph Neural Networks (GNNs). It combines a web-based Security Operations Center (SOC) dashboard, a Python backend, endpoint monitoring, and an Android companion application.

> **Project status:** Research and academic prototype. Detection results are experimental and should not be treated as a guarantee of zero-day attack detection or as a production-ready security solution.

## Features

- Security Operations Center dashboard.
- FastAPI backend and SQLite database.
- Graph Neural Network-based anomaly detection.
- Network event collection and risk correlation.
- Windows endpoint monitoring agent.
- Android companion application.
- Threat and incident management.
- Defensive response action interface.
- Authentication and user management.

## Technology Stack

| Component | Technologies |
|---|---|
| Frontend | React, Vite, Tailwind CSS |
| Backend | Python, FastAPI |
| Database | SQLite |
| AI / ML | PyTorch, PyTorch Geometric |
| Network monitoring | Python, psutil |
| Android | Kotlin, Android SDK |
| Development | VS Code, PowerShell, Git |

## Project Structure

```text
ZeroGuard/
|-- agent/                  # Windows monitoring agent
|-- android/                # Android companion application
|-- backend/                # FastAPI backend and GNN modules
|-- data/                   # Research data and processing files
|-- frontend/               # React dashboard
|-- .gitignore
`-- README.md
```

## Requirements

- Windows 10 or Windows 11
- Python 3.11
- Node.js and npm
- Android Studio (for Android development)
- Git

## Installation

### 1. Clone the repository

```powershell
git clone https://github.com/RohitM83/ZeroGuard.git
cd ZeroGuard
```

Clone the repository using the command above.

### 2. Create the Python environment

Run these commands from the project root:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r .\backend\requirements.txt
```

### 3. Start the backend

Open PowerShell in the project root:

```powershell
cd backend
& ..\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
```

The local API will be available at:

http://127.0.0.1:8000

### 4. Start the frontend

Open a second PowerShell window in the project root:

```powershell
cd frontend
npm install
Copy-Item .env.example .env.local
npm run dev
```

The dashboard will normally be available at:

http://localhost:5173

### 5. Start the Windows agent

Open another PowerShell window in the project root:

```powershell
.\.venv\Scripts\python.exe .\agent\zeroguard_agent.py
```

The Windows agent uses the backend address configured in its source code.

### 6. Android application

Open the `android` folder in Android Studio.

`ZEROGUARD_BACKEND_URL=http://YOUR_PC_LAN_IP:8000`

## Research Data

Research datasets and generated model files are not included in this repository. Obtain datasets from their respective official sources and follow their licensing and usage conditions.

## Security Notice

- Never publish passwords, authentication tokens, API keys, or private configuration files.
- Do not expose the development backend directly to the public internet.
- Review and test response actions before using them on real systems.
- Use controlled environments for security testing.

## Disclaimer

ZeroGuard is an experimental academic project. It is not a replacement for commercial endpoint detection, network security, or incident response platforms.
