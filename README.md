<h1 align="center">
  <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/shield-halved.svg" alt="SentinelX Logo" width="120" height="120"/>
  <br>
  SentinelX SIEM v2.0
</h1>

<p align="center">
  <b>A Lightweight, Scalable, Enterprise-Grade SIEM (Security Information and Event Management) for Modern Infrastructure & VPS Environments (cPanel/WHM Compatible).</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/Astro-FF5D01?style=for-the-badge&logo=astro&logoColor=white" alt="Astro">
  <img src="https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/OpenSearch-005FE6?style=for-the-badge&logo=opensearch&logoColor=white" alt="OpenSearch">
  <img src="https://img.shields.io/badge/MinIO-C42B1C?style=for-the-badge&logo=minio&logoColor=white" alt="MinIO">
  <img src="https://img.shields.io/badge/NATS-276EF1?style=for-the-badge&logo=nats&logoColor=white" alt="NATS">
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#documentation">Documentation</a> •
  <a href="README_es.md">🇪🇸 Leer en Español</a>
</p>

---

## 🛡️ Overview

**SentinelX SIEM v2.0** is an enterprise-grade security intelligence and log correlation platform. Designed to ingest, parse, normalize, and correlate security logs across distributed Linux infrastructure, web servers, and control panels (cPanel/WHM, DirectAdmin).

It leverages a **tri-storage architecture**:
1. **PostgreSQL**: System state, multi-tenant RBAC, rules, security lists, alerts, incidents, reporting metadata.
2. **OpenSearch**: High-throughput log event storage, full-text searching, and threat hunting analytics.
3. **MinIO (S3 Object Storage)**: Immutable forensic evidence packages and generated SOC PDF/HTML reports.

Whether deployed on a standalone VPS, cPanel server, or distributed Docker stack, SentinelX provides deep SOC observability with a **single-command installer**.

---

## ✨ Key Features

- **🚀 1-Command Automated Installer (`setup_sentinelx.sh`)**: Idempotent setup for clean Linux VPS (Ubuntu/Debian/AlmaLinux/RHEL) and cPanel/WHM servers. Logged to `/var/log/sentinelx/install.log`.
- **🏗️ Tri-Storage Tiering**: Clear separation between PostgreSQL (SOC State), OpenSearch (Logs & Analytics), and MinIO (Forensic S3 Evidence & Reports).
- **🛡️ Centralized Dynamic Security Lists**: Frontend-managed Whitelists, Rule Exceptions, BlacklistMaster inventory (`shared`, `pmg`, `ignore`), and Reference Lists with in-memory TTL caching and forensic ignore logs.
- **⚡ Asynchronous Ingest & Correlation Engine**: Decoupled `parsing_worker` and `engine_worker` loops running on NATS JetStream queues.
- **🌍 GeoIP & Behavioral Risk Scoring**: Enriches events with GeoIP location, ASN mapping, time-decay scoring, and entity tracking.
- **📊 SOC Reporting & Maintenance Engine**: Automated weekly/monthly/quarterly executive PDF/HTML report generation, S3 storage, and retention purge policies.
- **⚙️ Dedicated Systemd & cPanel Coexistence**: Operates cleanly under `/opt/sentinelx` with non-conflicting reserved ports (`8000`, `4321`, `5432`, `9200`, `9000`, `4222`).

---

## 🏗️ Enterprise Architecture v2.0

```mermaid
flowchart TD
    subgraph Clients["Monitored Servers & Agents"]
        A[Linux Agents / Syslog / cPanel / ModSec]
    end

    subgraph Ingestion["Ingestion Pipeline"]
        B[FastAPI Ingest Service]
        NATS[NATS JetStream Queue]
    end

    subgraph Processing["Worker Processing Layer"]
        PW[Parsing Worker\nLog Normalization & GeoIP]
        EW[Engine Worker v2\nCorrelation & Rule Decay]
    end

    subgraph Storage["Tri-Storage Architecture"]
        PG[(PostgreSQL 16\nSOC State & Security Lists)]
        OS[(OpenSearch 2.x\nEvents & Threat Hunting)]
        S3[(MinIO S3\nEvidence & Generated Reports)]
    end

    subgraph Interface["Management & Dashboard"]
        UI[Astro Web Frontend]
    end

    A -->|Logs Ingest / Agent API| B
    B -->|Publish Events| NATS
    NATS -->|Consume Raw| PW
    PW -->|Index Normalized Logs| OS
    PW -->|Persist State| PG
    EW -->|Evaluate Security Lists & Rules| PG
    EW -->|Fetch Logs| OS
    EW -->|Archive Evidence| S3
    UI <-->|REST API| B
    B <--> PG
    B <--> OS
    B <--> S3
```

---

## ⚡ Quick Start (Clean VPS / cPanel Install)

### 1. Clone the Repository
```bash
git clone https://github.com/caap1234/SIEM-SentinelXv2.0.git /opt/sentinelx
cd /opt/sentinelx
```

### 2. Run the Production Installer
```bash
chmod +x setup_sentinelx.sh
./setup_sentinelx.sh
```

**What the installer does automatically**:
1. Detects OS and installs system requirements.
2. Checks cPanel/WHM and configures CSF Firewall rules (`DOCKER="1"`).
3. Generates secure `.env` configuration file (`chmod 600`).
4. Creates Python `.venv` and builds Astro frontend static assets.
5. Runs `scripts/initial_setup.py` (Alembic DB migrations, admin account setup, MinIO bucket creation, OpenSearch indices, and security list seeds).
6. Registers Systemd services (`sentinelx-api`, `sentinelx-worker`, `sentinelx-ingest`, `sentinelx-frontend`).

---

## 📚 Documentation & Guides

Comprehensive technical documentation is available in the [`docs/`](docs/) directory:

- 📖 **[Installation Guide](docs/INSTALLATION_GUIDE.md)**: Hardware requirements, port matrix, step-by-step VPS/cPanel installation, and troubleshooting.
- 📋 **[Deployment Checklist](docs/DEPLOYMENT_CHECKLIST.md)**: Pre-production verification list.
- 🤖 **[Linux Agent Installation Guide](docs/AGENT_INSTALLATION.md)**: 1-line installation script and configuration for monitored client nodes.
- 📋 **[Security List Architecture Design](docs/LIST_MANAGEMENT_DESIGN.md)**: Dynamic whitelists, rule exceptions, and BlacklistMaster integration.
- 📑 **[SOC Reporting Architecture](docs/REPORTING_DESIGN.md)**: Executive/operational PDF & HTML report generation and retention policies.

---

## 🤝 System Verification & Testing

SentinelX includes an extensive test suite verifying end-to-end SOC flow, security list precedence, and API integrity:

```bash
# Run backend unit test suite (91 tests)
DATABASE_URL="sqlite:///:memory:" .venv/bin/pytest tests/unit/ -v

# Build frontend static assets
npm run build --prefix front
```

---

## 📄 License

This project is licensed under the open-source License. See [LICENSE](LICENSE) for details.
