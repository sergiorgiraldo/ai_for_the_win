# Vulnerability Intelligence Platform

A platform that aggregates vulnerability data, provides intelligent prioritization, and generates actionable remediation guidance.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export ANTHROPIC_API_KEY="your-key-here"

# Run the API server
python src/main.py

# Or run with Streamlit dashboard
streamlit run src/dashboard.py
```

## Project Structure

```
vuln-intel-platform/
├── README.md
├── requirements.txt
├── src/
│   ├── main.py              # FastAPI server
│   ├── dashboard.py         # Streamlit dashboard
│   ├── api/
│   │   ├── routes.py        # API endpoints
│   │   └── models.py        # Pydantic models
│   ├── data/
│   │   ├── nvd.py           # NVD data ingestion
│   │   ├── assets.py        # Asset inventory
│   │   └── scans.py         # Scan result import
│   ├── analysis/
│   │   ├── prioritizer.py   # Risk prioritization
│   │   ├── rag.py           # RAG for CVE Q&A
│   │   └── remediation.py   # Remediation guidance
│   └── reports/
│       └── generator.py     # Report generation
├── tests/
│   └── test_api.py
└── docker/
    └── docker-compose.yml
```

## Core Features Checklist

- [ ] CVE data ingestion (NVD API)
- [ ] Asset inventory integration
- [ ] Risk-based prioritization
- [ ] RAG-powered Q&A on CVEs
- [ ] Remediation recommendations

## Advanced Features Checklist

- [ ] Scan result import (Nessus/Qualys/Nuclei)
- [ ] Exploit availability tracking
- [ ] Patch tracking and verification
- [ ] Executive reporting
- [ ] Trend analysis

## API Endpoints

```
GET  /api/cves              # List CVEs
GET  /api/cves/{cve_id}     # Get CVE details
POST /api/assets            # Add asset
GET  /api/assets/{id}/vulns # Get asset vulnerabilities
POST /api/scans/import      # Import scan results
GET  /api/reports/executive # Generate executive report
POST /api/query             # RAG-powered Q&A
```

## Development Notes

Add your development notes here as you build the project.
