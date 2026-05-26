<div align="center">
  <h1>WebSentinel-AI</h1>
  <p><strong>AI-Powered Web Vulnerability Scanner &amp; Remediation Platform</strong></p>
  <p>
    <img src="https://img.shields.io/badge/python-3.12-blue?logo=python" alt="Python 3.12">
    <img src="https://img.shields.io/badge/FastAPI-0.115-green?logo=fastapi" alt="FastAPI">
    <img src="https://img.shields.io/badge/React-19-61DAFB?logo=react" alt="React 19">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
    <img src="https://img.shields.io/badge/AI-Ollama-8A2BE2" alt="AI Powered">
  </p>
  <br>
</div>

**WebSentinel-AI** is a professional, full-stack web vulnerability scanner that combines traditional security checks with local AI analysis (Ollama) to provide actionable, prioritized remediation plans. It features a real-time dashboard, REST API, and automated pipeline orchestration.

---

## Features

### AI-Powered Analysis
- **Local LLM Integration**: Uses Ollama (`qwen2.5:0.5b`) for intelligent vulnerability analysis
- **Smart Enrichment**: AI-generated CVSS estimates, exploitability assessments, and business impact context
- **Automated Attack Paths**: Visual graph showing how vulnerabilities chain together
- **Interactive AI Chat**: Context-aware Q&A about scan findings
- **Pipeline Intelligence**: AI decides whether to continue or stop based on findings severity

### Scanner Capabilities
| Check | Description |
|-------|-------------|
| `security_headers` | Missing security headers (CSP, HSTS, X-Frame-Options, etc.) |
| `ssl_tls` | SSL/TLS certificate validation and cipher strength |
| `reflected_xss` | Reflected cross-site scripting detection |
| `sql_injection` | SQL injection vulnerability scanning |
| `directory_enumeration` | Directory/file brute-force with smart filtering |
| `cookie_security` | Cookie flags audit (Secure, HttpOnly, SameSite) |
| `technology_detect` | Server technology fingerprinting |
| `dns_enumeration` | DNS record analysis (A, AAAA, MX, NS, TXT, CNAME, SOA) |
| `cve_lookup` | NVD-based CVE lookup for detected technologies |
| `subdomain_discovery` | crt.sh + DNS brute force subdomain enumeration |

### Pipeline Orchestration
- **Multi-stage pipelines**: Automates Web Scan → AI Analysis → Decision → Link Scan → AI Analysis → Final Report
- **Parallel execution**: Background task execution with WebSocket progress updates
- **AI decision gates**: Smart skip logic based on previous findings
- **Comprehensive reports**: Combined JSON/HTML/Markdown across all pipeline steps

### Platform Features
- **JWT Authentication**: Secure API access with bcrypt password hashing
- **WebSocket Realtime**: Live scan progress streaming to dashboard
- **Dashboard Analytics**: Severity distribution, resolution progress, activity feed
- **Findings Management**: Filter, search, and update finding status (open/fixed/false_positive/acknowledged)
- **Database Persistence**: All scans and findings saved to local SQLite database
- **Report Export**: Generate professional HTML, JSON, or Markdown reports
- **REST API**: Full OpenAPI documentation at `/docs`

---

## Architecture

```
web/                    # React + TypeScript frontend
  ├── src/
  │   ├── pages/        # Dashboard, WebScan, LinkScan, Pipeline, Findings, etc.
  │   ├── components/   # Reusable UI (AIChat, FindingAccordion, StatCard)
  │   ├── layouts/      # DashboardLayout with responsive nav
  │   ├── hooks/        # useWebSocket, API helpers
  │   └── stores/       # Zustand state (authStore, scanStore)

src/                    # Python backend
  ├── api/
  │   ├── main.py       # FastAPI app — all endpoints
  │   ├── auth.py       # JWT + bcrypt authentication
  │   ├── database.py   # SQLAlchemy async engine + migrations
  │   └── db_models.py  # User, Scan, Finding ORM models
  ├── scanner/
  │   ├── engine.py     # Scan orchestrator
  │   ├── models.py     # Pydantic models
  │   ├── checks/       # Vulnerability check plugins
  │   ├── noir.py       # OWASP Noir integration
  │   └── comprehensive.py # Multi-source scan (tech, subdomains, CVE, DNS)
  ├── ai/
  │   ├── ollama.py     # Ollama LLM client
  │   ├── enricher.py   # AI enrichment orchestrator
  │   ├── chat.py       # Context-aware Q&A service
  │   └── attack_path.py # Attack graph generation
  └── orchestrator/
      └── pipeline.py   # Pipeline engine with step execution
```

---

## Quick Start

### Prerequisites
- Python 3.12+
- Node.js 20+
- [Ollama](https://ollama.ai) with a model (e.g., `qwen2.5:0.5b`)
- (Optional) [OWASP Noir](https://github.com/owasp-noir/noir) via snap for advanced audits

### Backend Setup

```bash
# Clone and install
git clone https://github.com/galeanojuan2577/WebSentinel-AI.git
cd WebSentinel-AI
pip install -e ".[dev]"

# Start API server
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend Setup

```bash
cd web
npm install
npm run dev
```

### Verify Everything is Running

```bash
# API health check
curl http://localhost:8000/api/health

# Run a scan
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Open dashboard
open http://localhost:5173
```

### Using Docker

```bash
docker compose up --build
```

---

## API Reference

Full interactive API documentation is available at `http://localhost:8000/docs`

### Core Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Authenticate and receive JWT |
| `GET` | `/api/auth/me` | Current user info |
| `GET` | `/api/ai/check` | Ollama availability check |
| `GET` | `/api/checks` | List available vulnerability checks |
| `POST` | `/api/scan` | Start a web vulnerability scan |
| `GET` | `/api/scan/{id}` | Get scan results |
| `GET` | `/api/scan/{id}/report` | Generate report (html/json/markdown) |
| `POST` | `/api/link/scan-comprehensive` | Start comprehensive multi-source scan |
| `POST` | `/api/pipeline` | Start AI-orchestrated pipeline |
| `GET` | `/api/pipeline/{id}` | Get pipeline state |
| `GET` | `/api/pipeline/{id}/report` | Generate pipeline report |
| `GET` | `/api/findings` | List all findings with filters |
| `PATCH` | `/api/finding/{id}` | Update finding status |
| `GET` | `/api/stats` | Dashboard statistics |
| `POST` | `/api/ai/enrich/{scan_id}` | AI enrich scan findings |
| `POST` | `/api/ai/chat` | Interactive AI chat about findings |
| `POST` | `/api/ai/remediation-plan/{scan_id}` | Generate prioritized remediation plan |

### WebSocket

```
ws://localhost:8000/ws
```

Broadcasts real-time updates for scans and pipelines.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.12, FastAPI, SQLAlchemy (async), SQLite |
| **Frontend** | React 19, TypeScript, Vite 6, Tailwind CSS 4 |
| **AI Engine** | Ollama (local), qwen2.5:0.5b |
| **Scanner** | asyncio, httpx, OWASP Noir |
| **Auth** | JWT (PyJWT), bcrypt |
| **Infrastructure** | Docker, Docker Compose |

---

## Project Status

WebSentinel-AI is in active development. Current version: **0.3.0**

See the [issues](https://github.com/galeanojuan2577/WebSentinel-AI/issues) page for planned features and known issues.

---

## License

[MIT License](LICENSE) — feel free to use, modify, and distribute.

---

<div align="center">
  <sub>Built with ❤️ for the security community</sub>
</div>
