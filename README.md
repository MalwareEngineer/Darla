# Darla

Automated phishing kit analysis platform. Submit a URL, EML, or archive and Darla downloads, extracts, deobfuscates, renders, and scans the kit end-to-end — extracting IOCs, following redirect chains, fetching external JS infrastructure, and correlating threat actors across campaigns.

## Quick Start

```bash
git clone https://github.com/MalwareEngineer/Darla.git
cd Darla
cp .env.example .env        # edit credentials if needed
docker compose up -d
docker compose exec api alembic upgrade head
```

Verify everything is running:

```bash
curl http://localhost:8000/api/v1/health
```

The default configuration runs in **community / no-auth mode** suitable for
local evaluation by a single user. To deploy for a team behind an identity
provider, see [docs/auth/](docs/auth/README.md) — guides for Microsoft Entra,
Okta, Auth0, Keycloak, Authelia, Pocket-ID, and the generic OIDC pattern.

### YARA Rules

```bash
./scripts/update_yara_rules.sh
```

Downloads 890+ [t4d PhishingKit-Yara-Rules](https://github.com/t4d/PhishingKit-Yara-Rules) into `rules/t4d/`. Custom rules go anywhere in `rules/` — the directory is mounted read-only into workers. YARA scanning is optional; the pipeline runs without rules.

### Frontend

```bash
cd frontend
npm install
npm run dev       # http://localhost:5173
```

React + Vite + TailwindCSS dashboard for kit triage, investigation trees, indicator search, and campaign/actor management. Talks to the API at `:8000`.

## Architecture

```
                    ┌─────────────┐
                    │  React UI   │ :5173
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  FastAPI    │ :8000
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼─────┐ ┌───▼───┐ ┌─────▼─────┐
        │ PostgreSQL │ │ Redis │ │ RabbitMQ  │
        │    :5432   │ │ :6379 │ │   :5672   │
        └────────────┘ └───────┘ └─────┬─────┘
                                       │
                    ┌──────────────────┤
                    │                  │
         ┌─────────▼──────────┐  ┌────▼────────────┐
         │  worker-analysis   │  │ worker-downloads │
         │  worker-browser    │  │ worker-beat      │
         └────────────────────┘  └─────────────────┘
```

| Service | Image | Role |
|---------|-------|------|
| `postgres` | postgres:16-alpine | Primary database |
| `redis` | redis:7-alpine | Cache + Celery result backend |
| `rabbitmq` | rabbitmq:3.13-management | Celery message broker (management UI at `:15672`) |
| `api` | darla-api | FastAPI REST API |
| `worker-analysis` | darla-worker-analysis | Analysis pipeline (prefork, 10 processes) |
| `worker-downloads` | darla-worker-downloads | Kit downloads (prefork, 4 processes) |
| `worker-browser` | darla-worker-browser | Camoufox stealth browser (solo pool) |
| `worker-beat` | darla-worker-beat | Celery beat scheduler + stuck-kit recovery |

### Volumes

- `downloads` — raw downloaded kit files
- `extracted` — extracted/decompressed kit contents
- `./rules` — YARA rules (read-only mount)
- `./private` — private config files (read-only mount)

## Project Structure

```
src/darla/
├── api/              # FastAPI routes and dependencies
├── analysis/         # Core analysis logic
│   ├── deobfuscator.py   # PHP/HTML/JS deobfuscation
│   ├── extractor.py      # Archive extraction (ZIP/RAR/TAR)
│   ├── ioc_engine.py     # IOC extraction patterns and engine
│   ├── js_fetcher.py     # External JS fetching (<script src="...">)
│   └── patterns.py       # Regex patterns, benign domain lists, C2 keywords
├── models/           # SQLAlchemy ORM models
├── schemas/          # Pydantic request/response schemas
├── services/         # Business logic layer
├── tasks/            # Celery task definitions
│   ├── analysis.py       # 14-step analysis pipeline
│   ├── chain.py          # Redirect chain crawling, EML parsing, QR decode
│   ├── download.py       # Kit download + browser fallback
│   └── recovery.py       # Stuck-kit recovery
├── utils/            # HTTP client, helpers
├── main.py           # FastAPI app factory
├── celery_app.py     # Celery app initialization
├── config.py         # pydantic-settings (PK_ env prefix)
├── database.py       # Async SQLAlchemy engine + session
└── cli.py            # Typer CLI
```

## Analysis Pipeline

Each submitted kit runs through a 15-step Celery chain:

```
download → hash → extract → parse_eml → deobfuscate → decrypt_html →
fetch_external_js → yara_scan → extract_iocs → decode_qr → similarity →
correlate_actors → auto_assign_campaign → crawl_chain → finalize
```

| Step | What It Does |
|------|-------------|
| **download** | Fetch URL with redirect tracking, or store uploaded file |
| **hash** | SHA256, MD5, SHA1, TLSH |
| **extract** | ZIP, RAR, TAR, GZ with path traversal protection |
| **parse_eml** | Extract URLs, attachments, nested EMLs from email files |
| **deobfuscate** | PHP `eval(base64_decode(...))`, HTML entity encoding, JS XOR+base64+eval chains |
| **decrypt_html** | AES-GCM encrypted phishing pages (device code kits) |
| **fetch_external_js** | Follow `<script src="...">` to fetch external JS; CDN filtering, SSRF prevention, PHP source probing |
| **yara_scan** | t4d + custom rules on raw downloads, extracted files, and fetched JS |
| **extract_iocs** | C2 URLs (HTTP + WebSocket), emails, Telegram bots, SMTP creds, crypto wallets, domains, IPs, phone numbers |
| **decode_qr** | QR code extraction from images (quishing) |
| **similarity** | TLSH fuzzy hashing to find related kit variants |
| **correlate_actors** | Auto-create threat actors from high-confidence IOCs |
| **auto_assign_campaign** | Group kits by shared actors + TLSH similarity |
| **crawl_chain** | Follow redirects, email links, QR targets as child kits; browser render for JS-heavy pages |

### Chain Crawling

When a kit contains links (redirects, email URLs, QR codes), the pipeline spawns child kits that go through the same 15 steps. This creates an investigation tree:

```
EML (root kit)
├── nested_attachment.eml
│   └── obfuscated_loader.html
│       └── page.html (browser render)
│           └── _external_js/u1i2k.js (fetched)
```

## Configuration

All settings use the `PK_` env prefix. Key variables in `.env`:

```bash
# Infrastructure
POSTGRES_USER=darla
POSTGRES_PASSWORD=changeme
RABBITMQ_USER=darla
RABBITMQ_PASS=changeme

# Database
PK_DATABASE_URL=postgresql+asyncpg://...
PK_SYNC_DATABASE_URL=postgresql+psycopg2://...

# Analysis tuning
PK_MAX_KIT_SIZE_MB=50
PK_DOWNLOAD_TIMEOUT=30
PK_CHAIN_MAX_DEPTH=5
PK_EXTERNAL_JS_FETCH_ENABLED=true
PK_EXTERNAL_JS_FETCH_MAX_DEPTH=2
PK_EXTERNAL_JS_FETCH_MAX_FILES=10

# Browser rendering
PK_BROWSER_DOWNLOAD_ENABLED=true
PK_BROWSER_RENDER_ON_THIN_RESULTS=true
```

Full settings reference: `src/darla/config.py`

## Database Migrations

```bash
# Apply all migrations
docker compose exec api alembic upgrade head

# Create a new migration after model changes
docker compose exec api alembic revision --autogenerate -m "description"

# Check current revision
docker compose exec api alembic current
```

## API

Base URL: `http://localhost:8000/api/v1/`

### Submitting Kits

```bash
# URL submission (creates investigation + chain crawl)
curl -X POST http://localhost:8000/api/v1/investigations \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com/login"}'

# File upload (EML, ZIP, RAR, HTML)
curl -X POST http://localhost:8000/api/v1/kits/upload \
  -F "file=@phish.eml"

# Bulk file upload (max 50)
curl -X POST http://localhost:8000/api/v1/kits/upload/bulk \
  -F "files=@kit1.zip" -F "files=@kit2.zip"

# Reanalyze an existing kit
curl -X POST http://localhost:8000/api/v1/kits/{kit_id}/reanalyze
```

### Querying Results

```bash
# Kit details (includes children, campaigns, IOCs)
curl http://localhost:8000/api/v1/kits/{kit_id}

# Investigation tree
curl http://localhost:8000/api/v1/investigations/{id}/tree

# Search indicators
curl "http://localhost:8000/api/v1/indicators/search?query=cheacker.store"

# Find similar kits by TLSH
curl http://localhost:8000/api/v1/kits/{kit_id}/similar

# Analysis results for a kit
curl "http://localhost:8000/api/v1/analysis/results?kit_id={kit_id}"
```

### Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/kits` | Submit URL |
| POST | `/kits/upload` | Upload file |
| POST | `/kits/upload/bulk` | Bulk upload (max 50) |
| POST | `/investigations` | Create investigation from URL |
| GET | `/kits` | List kits (paginated, filterable) |
| GET | `/kits/{id}` | Kit detail |
| GET | `/kits/{id}/content` | View kit file content |
| GET | `/kits/{id}/similar` | TLSH similarity search |
| DELETE | `/kits/{id}` | Delete kit (cascades) |
| POST | `/kits/{id}/reanalyze` | Re-run analysis pipeline |
| GET | `/investigations/{id}/tree` | Investigation kit tree |
| GET | `/indicators` | List IOCs |
| GET | `/indicators/search` | Search IOCs by value |
| GET | `/indicators/stats` | IOC stats by type |
| GET | `/actors` | List threat actors |
| GET | `/campaigns` | List campaigns |
| GET | `/campaigns/{id}` | Campaign detail |
| GET | `/analysis/results` | Analysis results |

## CLI

```bash
# Submit
darla submit https://suspicious-site.com/login
darla submit phish.eml
darla submit kit.zip
darla submit --batch urls.txt

# Monitor
darla watch <kit_id>
darla status <kit_id>

# Search
darla kits list --status analyzed
darla kits similar <kit_id>
darla iocs list --type domain
darla iocs search "example.com"

# Investigations
darla investigations create https://suspicious-site.com/login
darla investigations tree <investigation_id>

# Management
darla campaigns list
darla actors list
darla health
darla worker recover
```

## Development

### Prerequisites

- Docker + Docker Compose
- Python 3.12+ (for local dev outside Docker)
- Node.js 18+ (for frontend)

### Local Dev Setup

```bash
# Create virtualenv
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install with all extras
pip install -e ".[dev,tlsh,yara,qr,browser]"

# Start infrastructure only
docker compose up -d postgres redis rabbitmq

# Run API locally
uvicorn darla.main:app --reload --port 8000

# Run worker locally
celery -A darla.celery_app worker -l info -Q analysis
```

### Tests

```bash
pytest
pytest tests/test_analysis/ -v
pytest --cov=darla
```

### Rebuilding Workers After Code Changes

```bash
docker compose build worker-analysis
docker compose up -d worker-analysis
```

Workers bake source code into the Docker image. After editing analysis logic, you must rebuild and restart. Verify the worker picked up changes:

```bash
docker compose logs worker-analysis --tail 5  # look for "celery@... ready."
```

### Adding a New Pipeline Step

1. Add a Celery task in `src/darla/tasks/analysis.py`
2. Add it to the chain in `_post_download_steps()`
3. If it needs a new `AnalysisType`, add the enum value and create an Alembic migration
4. Use `upsert_analysis_result()` for DB writes (handles dedup on reanalysis)
5. Return `{**prev_result, "your_key": value}` to pass data through the chain

### Adding IOC Patterns

1. Add regex to `src/darla/analysis/patterns.py`
2. Add extraction logic in `src/darla/analysis/ioc_engine.py` (`_extract_urls()` or new method)
3. Use existing `IndicatorType` enum values, or add a new one with a migration

## License

MIT
