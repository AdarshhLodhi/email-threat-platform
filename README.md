# AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

## Overview

This is a defensive cybersecurity research and prototype platform designed for hackathons. It transforms a suspicious email into an investigable forensic case. 

**IMPORTANT DISCLAIMER**: This is a defensive cybersecurity tool. It does not perform offensive capabilities, credential harvesting, malware delivery, deanonymization, or automated active responses against real infrastructure.

The platform provides a clear distinction between:
- **Detection**: Ingesting an EML file or raw text to identify suspicious activity.
- **Investigation**: Parsing SMTP headers, validating authentication (SPF, DKIM, DMARC), and extracting Indicators of Compromise (IOCs).
- **Infrastructure Correlation**: Geolocation mapping and ASN lookup of the originating IP address.
- **Evidence Generation**: Creating standardized forensic reports.

## Features

1. **Email Parser & Header Forensics**
   - Extracts sender, recipient, subject, dates, and hops.
   - Detects spoofing and validates SPF, DKIM, and DMARC alignments.
2. **AI Threat Classification Engine**
   - Built with Scikit-learn (TF-IDF + Naive Bayes).
   - Classifies emails into categories: Phishing, Malware/Ransomware, Spam, Benign, CEO Fraud, Financial Fraud.
3. **Infrastructure & Geolocation Mapping**
   - Translates originating IP to geographical coordinates using a mocked Demo Geolocation API or standard services.
4. **Domain & Lookalike Analysis**
   - Checks for homoglyphs and typosquatting in sender domains.
5. **Modern Glassmorphism UI**
   - Developed in React with Vite and Vanilla CSS.
   - Dashboards for case management and executive summaries.

## Tech Stack

- **Backend**: Python, FastAPI, SQLAlchemy (SQLite), Scikit-learn, NetworkX, Uvicorn.
- **Frontend**: React (TypeScript), Vite, React Router, Recharts, React-Leaflet, Lucide-React.
- **Design System**: Vanilla CSS with customized CSS variables and glassmorphism themes.

## Getting Started

### Local Development (Without Docker)

1. **Backend**:
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   uvicorn app.main:app --reload --port 8000
   ```
2. **Frontend**:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

### Production Deployment (Docker Compose)

The project is fully containerized for production deployment.

1. Ensure Docker and Docker Compose are installed.
2. Create a `.env` file in the `backend` directory based on `backend/.env.example`.
3. Build and start the cluster:
   ```bash
   docker compose up --build -d
   ```
4. Access the platform:
   - Frontend: `http://localhost:80`
   - Backend API: `http://localhost:8000`

The Docker environment uses **PostgreSQL** for the database, **Gunicorn** for the backend API, and **Nginx** to serve the optimized frontend build.

## API Endpoints

- `POST /api/v1/analyze`: Upload and analyze an `.eml` file or raw text.
- `GET /api/v1/cases`: Retrieve all forensic cases.
- `GET /api/v1/cases/{case_id}`: Retrieve details for a specific case.
- `GET /api/v1/reports/{case_id}/forensic`: Generate a forensic text report for a case.

## Architecture

```
email-threat-platform/
│
├── backend/                  # FastAPI Application
│   ├── app/
│   │   ├── main.py           # API Entrypoint
│   │   ├── database.py       # SQLite connection
│   │   ├── models/           # SQLAlchemy DB Models
│   │   ├── schemas/          # Pydantic validation schemas
│   │   ├── routers/          # API Routers
│   │   └── services/         # Core logic (AI, Geo, Auth, Parsers)
│   └── models/               # Pickled ML models (generated)
│
├── frontend/                 # React Application
│   ├── src/
│   │   ├── index.css         # Global Glassmorphism Styles
│   │   ├── App.tsx           # Router Configuration
│   │   └── pages/            # Dashboard, Upload, Case Details
│   └── package.json
│
├── data/                     # Threat dataset CSV
├── scripts/                  # Training and seeding scripts
└── README.md
```
