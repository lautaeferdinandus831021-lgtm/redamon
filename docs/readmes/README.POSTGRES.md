# PostgreSQL Database

PostgreSQL database for storing WhiteHat project configurations and user data. Uses Prisma ORM for schema management and query building.

## Overview

The PostgreSQL database stores:

- **Users** - User accounts for project ownership
- **Projects** - Target configurations with 169+ tunable parameters

This replaces the need for `params.py` configuration files, allowing project-specific settings to be managed through the webapp UI.

## Quick Start

```bash
# 1. Start PostgreSQL
cd services/postgres_db
docker-compose up -d

# 2. Verify connection
docker exec whitehat-postgres pg_isready -U whitehat -d whitehat

# 3. Initialize schema (from webapp)
cd ../webapp
npx prisma generate
npx prisma db push
```

## Architecture

```mermaid
flowchart TB
    subgraph Webapp["Webapp :3000"]
        Prisma[Prisma Client]
        API[API Routes]
    end

    subgraph PostgreSQL["PostgreSQL :5432"]
        Users[(users)]
        Projects[(projects)]
    end

    subgraph Recon["Recon Container"]
        Settings[project_settings.py]
    end

    Prisma --> Users
    Prisma --> Projects
    API --> Prisma
    Settings -->|GET /api/projects/:id| API
```

## Database Schema

### Users Table

| Column | Type | Description |
|--------|------|-------------|
| id | CUID | Primary key |
| name | String | User display name |
| email | String | Unique email |
| created_at | DateTime | Creation timestamp |
| updated_at | DateTime | Last update |

### Projects Table

The projects table contains 169+ configuration parameters grouped by category:

#### Target Configuration
| Column | Default | Description |
|--------|---------|-------------|
| target_domain | "" | Root domain to scan |
| subdomain_list | ["gpigs."] | Specific subdomains to scan |
| verify_domain_ownership | false | Require ownership verification |
| scan_modules | [...] | Active scan modules |

#### Port Scanner (Naabu)
| Column | Default | Description |
|--------|---------|-------------|
| naabu_top_ports | "1000" | Number of top ports |
| naabu_rate_limit | 1000 | Packets per second |
| naabu_scan_type | "s" | SYN scan |
| naabu_exclude_cdn | false | Skip CDN IPs |

#### HTTP Prober (Httpx)
| Column | Default | Description |
|--------|---------|-------------|
| httpx_threads | 50 | Concurrent threads |
| httpx_timeout | 10 | Request timeout |
| httpx_probe_tech_detect | true | Technology detection |
| httpx_probe_tls_info | true | TLS certificate info |

#### Vulnerability Scanner (Nuclei)
| Column | Default | Description |
|--------|---------|-------------|
| nuclei_severity | ["critical", "high", "medium", "low"] | Severity filter |
| nuclei_dast_mode | true | Enable DAST fuzzing |
| nuclei_rate_limit | 100 | Requests per second |
| nuclei_timeout | 10 | Template timeout |

#### Web Crawler (Katana)
| Column | Default | Description |
|--------|---------|-------------|
| katana_depth | 3 | Crawl depth |
| katana_max_urls | 500 | Max URLs to crawl |
| katana_js_crawl | true | JavaScript rendering |

#### URL Discovery (GAU)
| Column | Default | Description |
|--------|---------|-------------|
| gau_enabled | true | Enable passive discovery |
| gau_providers | [...] | Archive sources |
| gau_max_urls | 1000 | Max URLs to fetch |

#### Security Checks
| Column | Default | Description |
|--------|---------|-------------|
| security_check_enabled | true | Enable security checks |
| security_check_tls_expiry_days | 30 | TLS expiry warning threshold |
| security_check_spf_missing | true | Check for SPF records |

For the complete schema, see [webapp/prisma/schema.prisma](../../webapp/prisma/schema.prisma).

## Docker Configuration

### docker-compose.yml

```yaml
services:
  postgres:
    image: postgres:16-alpine
    container_name: whitehat-postgres
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-whitehat}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set - run whitehat.sh (STRIDE S13)}
      POSTGRES_DB: ${POSTGRES_DB:-whitehat}
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U whitehat -d whitehat"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
```

### Environment Variables

Create a `.env` file:

```bash
POSTGRES_USER=whitehat
POSTGRES_PASSWORD=your_secure_password
POSTGRES_DB=whitehat
```

## Prisma Integration

### Connection URL

In `webapp/.env.local` (replace `<POSTGRES_PASSWORD>` with the value from your
root `.env` — `whitehat.sh` generates a strong one on a fresh install; the host
port is published on `127.0.0.1` only):

```bash
DATABASE_URL="postgresql://whitehat:<POSTGRES_PASSWORD>@127.0.0.1:5432/whitehat?schema=public"
```

### Common Commands

```bash
# Generate Prisma client
npx prisma generate

# Push schema changes
npx prisma db push

# Open Prisma Studio (GUI)
npx prisma studio

# Reset database
npx prisma db push --force-reset

# Create migration
npx prisma migrate dev --name description
```

## Recon Integration

When recon runs with `PROJECT_ID` and `WEBAPP_API_URL` environment variables, it fetches settings from the webapp API:

```python
# recon/project_settings.py
def fetch_project_settings(project_id: str, webapp_url: str) -> dict:
    """Fetch project settings from webapp API."""
    response = requests.get(f"{webapp_url}/api/projects/{project_id}")
    project = response.json()

    return {
        'TARGET_DOMAIN': project['targetDomain'],
        'SUBDOMAIN_LIST': project['subdomainList'],
        'SCAN_MODULES': project['scanModules'],
        # ... 169+ parameters mapped from camelCase to SCREAMING_SNAKE_CASE
    }
```

This allows each project to have its own configuration without modifying `params.py`.

## Backup & Restore

### Backup

```bash
# Create backup
docker exec whitehat-postgres pg_dump -U whitehat whitehat > backup.sql

# Create compressed backup
docker exec whitehat-postgres pg_dump -U whitehat whitehat | gzip > backup.sql.gz
```

### Restore

```bash
# Restore from backup
docker exec -i whitehat-postgres psql -U whitehat whitehat < backup.sql

# Restore from compressed backup
gunzip -c backup.sql.gz | docker exec -i whitehat-postgres psql -U whitehat whitehat
```

## Useful Commands

```bash
# Connect to PostgreSQL shell
docker exec -it whitehat-postgres psql -U whitehat -d whitehat

# List tables
\dt

# Describe table
\d projects

# Query projects
SELECT id, name, target_domain FROM projects;

# Check database size
SELECT pg_size_pretty(pg_database_size('whitehat'));
```

## Troubleshooting

### Connection Refused

1. Check PostgreSQL is running:
   ```bash
   docker-compose ps
   ```

2. Verify health check:
   ```bash
   docker exec whitehat-postgres pg_isready -U whitehat -d whitehat
   ```

### Schema Out of Sync

If Prisma schema doesn't match database:

```bash
# Force push schema (destructive)
cd webapp
npx prisma db push --force-reset

# Or create migration
npx prisma migrate dev
```

### Password Authentication Failed

Check `.env` credentials match `webapp/.env.local`:

```bash
# services/postgres_db/.env
POSTGRES_PASSWORD=your_password

# webapp/.env.local
DATABASE_URL="postgresql://whitehat:your_password@localhost:5432/whitehat"
```
