# WhiteHat Web Application

Production-ready Next.js 16 web application with Neo4j integration, PostgreSQL project storage, and integrated recon control.

## Tech Stack

- **Framework**: Next.js 16.1 with App Router & Turbopack
- **Runtime**: Node.js 22
- **Graph Database**: Neo4j 5.x (attack surface data)
- **Relational Database**: PostgreSQL 16 with Prisma ORM (project settings)
- **Language**: TypeScript 5.7
- **UI**: React 19.2
- **Production**: Docker with multi-stage builds

## Project Structure

```
webapp/
├── prisma/
│   └── schema.prisma          # Database schema (169+ project params)
├── src/
│   ├── app/                    # Next.js App Router
│   │   ├── api/               # API Routes
│   │   │   ├── health/        # Health check endpoint
│   │   │   ├── neo4j/         # Neo4j query endpoint
│   │   │   ├── nuclei-templates/ # Custom nuclei template CRUD (global)
│   │   │   ├── projects/      # Project CRUD endpoints
│   │   │   └── recon/         # Recon control endpoints
│   │   │       └── [projectId]/
│   │   │           ├── start/     # POST - Start recon
│   │   │           ├── status/    # GET - Check status
│   │   │           ├── logs/      # GET - SSE log stream
│   │   │           └── download/  # GET - Download JSON
│   │   ├── graph/             # Graph visualization page
│   │   │   └── components/
│   │   │       ├── GraphToolbar/      # Recon controls
│   │   │       ├── ReconLogsDrawer/   # Real-time logs
│   │   │       ├── ReconConfirmModal/ # Confirmation dialog
│   │   │       └── AIAssistantDrawer/ # Agent chat & tool confirmation UI
│   │   ├── layout.tsx         # Root layout
│   │   ├── page.tsx           # Home page
│   │   └── globals.css        # Global styles
│   ├── components/            # React components
│   ├── hooks/                 # Custom hooks
│   │   ├── useReconStatus.ts  # Status polling
│   │   ├── useReconSSE.ts     # SSE log streaming
│   │   └── useAgentWebSocket.ts # Agent WebSocket (queries, approvals, tool confirmation)
│   ├── lib/
│   │   ├── neo4j.ts           # Neo4j driver
│   │   ├── prisma.ts          # Prisma client
│   │   ├── recon-types.ts     # TypeScript types
│   │   ├── websocket-types.ts # Agent WebSocket message types
│   │   └── hard-guardrail.ts  # Deterministic domain blocklist (gov/mil/edu/int)
│   └── providers/             # React context providers
├── public/                    # Static assets
├── Dockerfile                 # Production multi-stage build
├── docker-compose.yml         # Production compose
└── package.json
```

---

## Authorization & Multi-User Access Control

WhiteHat is single-admin / multi-user: one admin manages many standard users, and **each standard user may only access their own data** (projects, graph, conversations, scans, reports, settings). Authentication (a JWT in the httpOnly `whitehat-auth` cookie, verified in `middleware.ts` and `lib/session.ts`) proves *who* is calling; **authorization** proves they *own* what they touch.

**Effective user.** `getEffectiveUser()` (`lib/session.ts`) returns the identity a request is scoped to:

- standard user -> their own id (any impersonation input is ignored);
- admin, not simulating -> their own id;
- admin simulating user X -> X, and only X (via a signed httpOnly `whitehat-act-as` cookie set by the admin-only `POST /api/auth/act-as`).

So an admin has no "see everything" mode; to view a user's data they explicitly *switch to* that user (see the User-Management wiki page).

**Guards (`lib/access.ts`).** Every API route that reads or mutates a per-user resource must scope to the effective user. Use:

- `guardProject(projectId)` - one-call guard for `[projectId]` routes (scan/analytics/workspace/graph): resolves the effective user and 404s if they don't own the project.
- `requireProjectAccess(eff, projectId)` / `requireConversationAccess(eff, id)` / `requireProjectScopedResource(eff, loadProjectId)` - when you already hold the effective user.
- `ownerScope(eff)` - a Prisma `where` fragment (`{ userId }`) for list endpoints; never trust a client-supplied `userId`/`projectId`.
- `requireUserAccess(request, targetUserId)` (`lib/session.ts`) - for `users/[id]/*` READ routes (own-or-admin, with an `X-Internal-Key` carve-out for the agent). **Write** routes (POST `/api/users`, PUT/DELETE `/api/users/[id]`, POST `/api/users/[id]/llm-providers`) require an admin/owner **session** and do NOT accept the internal-key bypass, so an internal key can no longer mint an admin (STRIDE S2/E2). GET `/api/users/[id]/settings` additionally accepts the lower-tier `SCANNER_API_KEY` via `isScannerRequest` (STRIDE S3/E6).

Cross-user access is reported as **404** (anti-enumeration). Enforcement is **on by default** and fails closed; set `ACCESS_ENFORCE=0` only to run a temporary log-only (`[BOLA] would-block ...`) observation phase.

**Internal callers (STRIDE S2/E2 + S3/E6).** The agent and cypherfix present `X-Internal-Key` (constant-time compared) and are carved out via `isInternalRequest(request)`, restricted to an **allowlist** of the exact routes they call (llm-providers/settings/tradecraft/projects GET, codefix-sandbox, conversations/by-session/*, remediations/*, global/tunnel-config). The allowlist is **log-only by default**; set `INTERNAL_KEY_ALLOWLIST_ENFORCE=true` to block off-allowlist internal-key requests once logs confirm only known routes. Scanners instead present a **lower-tier `SCANNER_API_KEY`** (`isScannerRequest`), accepted ONLY on GET `/api/users/[id]/settings` and GET `/api/projects/[id]` - never llm-providers or user-CRUD, so a compromised scanner cannot harvest LLM keys or mint an admin.

**When adding a route:** derive identity from `getEffectiveUser()`/`requireUserAccess`, never from a query/body `userId`/`projectId`; add the ownership guard before any data read; and cover it with a cross-user 403/404 test. The live end-to-end check is `tests/test_e2e_bola_live.sh`.

---

## Prerequisites

**Neo4j must be running first.** This webapp connects to the existing Neo4j instance in `../graph_db/`.

```bash
# Start Neo4j from the graph_db folder
cd ../graph_db
docker compose up -d

# Verify Neo4j is running
# Neo4j Browser: http://localhost:7474
```

---

## Development Setup

```bash
# 1. Make sure Neo4j is running (see Prerequisites above)

# 2. Install dependencies
npm install

# 3. Environment is auto-configured via docker-compose defaults
# All API keys and settings are managed from the webapp UI at /settings

# 4. Run development server (with hot reload)
npm run dev

# 5. Access the application
# Web App: http://localhost:3000
```

The development server uses Turbopack for fast refresh - changes to your code are reflected instantly.

---

## Production Build & Deployment

### Build Production Image

```bash
# Build the production image
docker build -t whitehat-webapp:latest .

# Run production container locally
docker run -p 3000:3000 \
  --network graph_db_default \
  -e NEO4J_URI=bolt://whitehat-neo4j:7687 \
  -e NEO4J_USER=neo4j \
  -e NEO4J_PASSWORD=your_password \
  whitehat-webapp:latest
```

### Production with Docker Compose

```bash
# 1. Make sure Neo4j is running (from graph_db folder)
cd ../graph_db && docker compose up -d && cd ../webapp

# 2. Environment is auto-configured via docker-compose defaults
# All API keys and settings are managed from the webapp UI at /settings

# 3. Build and start services
docker compose up -d --build

# 4. View logs
docker compose logs -f webapp

# 5. Check health
curl http://localhost:3000/api/health
```

### Production Image Details

The production Dockerfile uses a multi-stage build:

1. **deps**: Installs production dependencies
2. **builder**: Builds the Next.js application
3. **runner**: Minimal runtime image (~150MB)

Features:
- Non-root user for security
- Standalone output for minimal image size
- Health check endpoint included
- Optimized for container orchestration

---

## AWS Deployment Guide

### Prerequisites

- AWS CLI configured
- ECR repository created
- ECS cluster or EKS cluster ready

### 1. Push to Amazon ECR

```bash
# Authenticate with ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com

# Tag image
docker tag whitehat-webapp:latest \
  YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/whitehat-webapp:latest

# Push image
docker push \
  YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/whitehat-webapp:latest
```

### 2. ECS Fargate Deployment

Create a task definition (`task-definition.json`):

```json
{
  "family": "whitehat-webapp",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::YOUR_ACCOUNT:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "webapp",
      "image": "YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/whitehat-webapp:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "NODE_ENV", "value": "production"},
        {"name": "NEO4J_URI", "value": "bolt://your-neo4j-endpoint:7687"}
      ],
      "secrets": [
        {
          "name": "NEO4J_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:YOUR_ACCOUNT:secret:whitehat/neo4j"
        }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "wget -q --spider http://localhost:3000/api/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/whitehat-webapp",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

Deploy:
```bash
# Register task definition
aws ecs register-task-definition --cli-input-json file://task-definition.json

# Create service with ALB
aws ecs create-service \
  --cluster your-cluster \
  --service-name whitehat-webapp \
  --task-definition whitehat-webapp \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}" \
  --load-balancers "targetGroupArn=arn:aws:elasticloadbalancing:...,containerName=webapp,containerPort=3000"
```

### 3. Auto Scaling Configuration

```bash
# Register scalable target
aws application-autoscaling register-scalable-target \
  --service-namespace ecs \
  --scalable-dimension ecs:service:DesiredCount \
  --resource-id service/your-cluster/whitehat-webapp \
  --min-capacity 2 \
  --max-capacity 100

# Create scaling policy (target tracking)
aws application-autoscaling put-scaling-policy \
  --service-namespace ecs \
  --scalable-dimension ecs:service:DesiredCount \
  --resource-id service/your-cluster/whitehat-webapp \
  --policy-name cpu-tracking \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration '{
    "TargetValue": 70.0,
    "PredefinedMetricSpecification": {
      "PredefinedMetricType": "ECSServiceAverageCPUUtilization"
    },
    "ScaleOutCooldown": 60,
    "ScaleInCooldown": 120
  }'
```

### 4. Neo4j on AWS Options

**Option A: Amazon Neptune (Managed)**
- Fully managed graph database
- Compatible with openCypher (Neo4j query language)

**Option B: Neo4j AuraDB**
- Neo4j's managed cloud service
- Available on AWS Marketplace

**Option C: Self-hosted on EC2/EKS**
```bash
# EC2 with Docker
docker run -d \
  -p 7474:7474 -p 7687:7687 \
  -v /data/neo4j:/data \
  -e NEO4J_AUTH=neo4j/your_password \
  -e NEO4J_dbms_memory_heap_max__size=4G \
  neo4j:5-enterprise
```

---

## API Reference

### Health Check
```
GET /api/health
```
Returns service health status:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-02T12:00:00.000Z",
  "services": {
    "neo4j": "connected"
  }
}
```

### Neo4j Status
```
GET /api/neo4j
```
Returns database connection status and node count.

### Execute Query
```
POST /api/neo4j
Content-Type: application/json

{
  "query": "MATCH (n) RETURN n LIMIT 10",
  "params": {}
}
```

### Recon Control API

The webapp provides endpoints to control reconnaissance scans via the Recon Orchestrator.

#### Start Recon
```
POST /api/recon/[projectId]/start
Content-Type: application/json

{
  "userId": "user-123"
}
```

Starts a new recon scan for the specified project. The recon container will:
1. Fetch project settings from `GET /api/projects/{projectId}`
2. Execute the scan pipeline
3. Stream logs in real-time
4. Update Neo4j with results

**Response:**
```json
{
  "project_id": "project-123",
  "status": "starting",
  "container_id": "abc123...",
  "started_at": "2024-01-15T10:30:00Z"
}
```

#### Get Recon Status
```
GET /api/recon/[projectId]/status
```

Returns current recon status:
```json
{
  "project_id": "project-123",
  "status": "running",
  "current_phase": "Port Scanning",
  "phase_number": 2,
  "total_phases": 7,
  "started_at": "2024-01-15T10:30:00Z"
}
```

**Status Values:** `idle`, `starting`, `running`, `completed`, `error`, `stopping`

#### Stream Recon Logs (SSE)
```
GET /api/recon/[projectId]/logs
Accept: text/event-stream
```

Server-Sent Events stream of real-time log output:
```
event: log
data: {"log": "Starting port scan...", "timestamp": "...", "phase": "Port Scanning", "phaseNumber": 2, "level": "info"}

event: complete
data: {"status": "completed", "completedAt": "..."}
```

#### Stop Recon
```
POST /api/recon/[projectId]/stop
```

Gracefully stops a running recon container.

#### Download Recon JSON
```
GET /api/recon/[projectId]/download
```

Downloads the recon output JSON file for the project.

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NEO4J_URI` | Neo4j connection URI | `bolt://localhost:7687` (dev) / `bolt://whitehat-neo4j:7687` (Docker) |
| `NEO4J_USER` | Neo4j username | `neo4j` |
| `NEO4J_PASSWORD` | Neo4j password | (set in .env.local) |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://whitehat:<POSTGRES_PASSWORD>@localhost:5432/whitehat` (password from `.env`, generated on fresh install; host port loopback-only) |
| `RECON_ORCHESTRATOR_URL` | Recon orchestrator service URL | `http://localhost:8010` |
| `ORCHESTRATOR_API_KEY` | Sent as `X-Orchestrator-Key` on every orchestrator call; must match the orchestrator's value (auto-generated in `.env`) | (generated) |
| `INTERNAL_API_KEY` | Master service-to-service key. Attached (as `x-internal-key`) when the webapp proxies to the agent's guarded endpoints; accepted (constant-time) on the internal-route allowlist | (generated) |
| `SCANNER_API_KEY` | Lower-tier scanner token (S3/E6). Accepted only on GET `settings` + GET `projects`; cannot mint admins or read llm-providers | (generated) |
| `INTERNAL_KEY_ALLOWLIST_ENFORCE` | When `true`, block internal-key requests to routes outside the allowlist; default is log-only | (unset = log-only) |
| `NODE_ENV` | Environment mode | `development` |
| `PORT` | Application port | `3000` |

---

## Recon Integration

The webapp integrates with the Recon Orchestrator to provide real-time reconnaissance control.

### React Hooks

**useReconStatus** - Polls recon status with smart intervals:
```typescript
import { useReconStatus } from '@/hooks/useReconStatus'

const { state, startRecon, stopRecon, isLoading, error } = useReconStatus({
  projectId: 'project-123',
  enabled: true,
  onComplete: () => refetchGraph(),
  onStatusChange: (status) => console.log('Status:', status)
})
```

**useReconSSE** - Connects to real-time log stream:
```typescript
import { useReconSSE } from '@/hooks/useReconSSE'

const { logs, currentPhase, currentPhaseNumber, isConnected, clearLogs } = useReconSSE({
  projectId: 'project-123',
  enabled: state?.status === 'running',
  onPhaseChange: (phase, num) => console.log(`Phase ${num}: ${phase}`),
  onComplete: (status) => console.log('Recon finished:', status)
})
```

### Components

| Component | Description |
|-----------|-------------|
| `GraphToolbar` | Contains Start Recon and Download JSON buttons |
| `ReconConfirmModal` | Confirmation dialog before starting recon (warns about data replacement) |
| `ReconLogsDrawer` | Slide-out panel showing real-time logs with phase progress |
| `KaliTerminal` | Interactive Kali sandbox terminal (xterm.js) with WebSocket PTY, auto-reconnect, fullscreen, dark theme |

### AI Agent Chat (AIAssistantDrawer)

The `AIAssistantDrawer` is the primary interface for interacting with the WhiteHat pentesting agent. It communicates over WebSocket via the `useAgentWebSocket` hook and renders a real-time timeline of agent activity.

The component is split into a thin orchestrator (`AIAssistantDrawer.tsx`, ~426 lines) that composes purpose-built hooks and sub-components. All files live in `webapp/src/app/graph/components/AIAssistantDrawer/`.

#### Sub-components

| Component | Description |
|-----------|-------------|
| `AIAssistantDrawer` | Thin orchestrator — wires hooks together, renders sub-components |
| `DrawerHeader` | Header bar — connection status, history toggle, new chat, download, close |
| `PhaseIndicatorBar` | Phase badge, tool icons, attack skill badge, stealth/deep-think toggles, model badge, settings dropdown |
| `ChatArea` | Scrollable message list — renders grouped items, loading eye, empty state |
| `InputArea` | Textarea, send/stop/resume buttons, Chat Skill picker (lightning bolt), `/skill` autocomplete, active skill badge |
| `ApprovalDialog` | Phase-transition approval overlay |
| `QuestionDialog` | Agent Q&A overlay (text / single-choice / multi-choice) |
| `SettingsModal` | Agent behaviour / tool matrix / attack skills settings overlay |
| `ModelPickerModal` | Model search and selection modal |
| `ApiKeyModal` | API key input modal |
| `SuggestionPanels` | Suggestion accordion shown in empty chat state |
| `AgentTimeline` | Chronological timeline of thinking steps, tool executions, plan waves, and confirmations |
| `ToolExecutionCard` | Individual tool execution card — tool name, args, output chunks, status, **Allow/Deny** buttons |
| `PlanWaveCard` | Parallel wave card — groups tools in a plan wave, **Allow/Deny** for dangerous waves |
| `TodoListWidget` | Agent's live task list |
| `FileDownloadCard` | Download card for agent-generated files (reports, exports) |

#### Custom Hooks (`hooks/`)

| Hook | Owns |
|------|------|
| `useWebSocketHandler` | WebSocket message dispatch (18+ message types) |
| `useSendHandlers` | `handleSend`, `handleApproval`, `handleAnswer`, `handleStop`, `handleResume`, `handleSkillCommand`, `activateSkill`, active skill state |
| `useChatState` | `chatItems`, loading/stopped/phase state, `groupedChatItems` memo |
| `useInteractionState` | Approval / Q&A / tool-confirmation state + double-submit refs |
| `useConversationRestoration` | Conversation history, load/delete, `handleSelectConversation` |
| `useScrollBehavior` | Auto-scroll, `scrollToBottom`, `checkIfAtBottom` |
| `useApiKeyModal` | `API_KEY_INFO`, missing key detection, key save flow |
| `useModelPicker` | Model list fetch, search filtering, model selection |
| `useSettingsModal` | Project form state, debounced save, settings dropdown |
| `useAttackSkillData` | Attack skill list fetch |
| `useLoadingWord` | Rotating loading status word |
| `useDownloadMarkdown` | Markdown report generation and download |

#### Static files

| File | Content |
|------|---------|
| `types.ts` | `Phase`, `Message`, `FileDownloadItem`, `ChatItem`, `AIAssistantDrawerProps` |
| `phaseConfig.ts` | `PHASE_CONFIG`, `KNOWN_ATTACK_PATH_CONFIG`, `getAttackPathConfig()`, `formatModelDisplay()` |
| `suggestionData.ts` | Suggestion panel data (informational / exploitation / post-exploitation groups) |

#### Tool Confirmation in the Chat

When `REQUIRE_TOOL_CONFIRMATION` is enabled in Project Settings, the agent pauses before executing dangerous tools and the chat renders inline confirmation cards:

- **Single tool**: A `ToolExecutionCard` appears with `status: "pending_approval"` and **Allow / Deny** buttons
- **Parallel wave**: A `PlanWaveCard` appears listing all dangerous tools in the wave with **Allow / Deny** buttons
- The chat input is disabled while awaiting confirmation
- On **Allow**: the card transitions to `running` and the tool executes
- On **Deny**: the card shows an error state and the agent re-plans with an alternative approach

When the setting is disabled, an orange warning badge appears in the chat header.

#### WebSocket Hook API

```typescript
const {
  sendQuery,              // Send user question
  sendApproval,           // Respond to phase transition approval
  sendToolConfirmation,   // Respond to tool confirmation (approve/modify/reject)
  sendAnswer,             // Answer agent's question
  sendGuidance,           // Send mid-execution guidance
  sendStop,               // Stop agent execution
  sendResume,             // Resume from checkpoint
} = useAgentWebSocket({ userId, projectId, sessionId, onMessage })
```

### Phase Detection

The recon orchestrator automatically detects scan phases from log output:

| Phase | Description |
|-------|-------------|
| 1 | Domain Discovery |
| 2 | Port Scanning |
| 3 | HTTP Probing |
| 4 | Resource Enumeration |
| 4b | JS Recon (post-resource_enum, if enabled) |
| 5 | Vulnerability Scanning |
| 6 | MITRE Enrichment |
| 7 | GitHub Secret Hunt |

---

## Useful Commands

```bash
# Development
npm run dev              # Start dev server with Turbopack (hot reload)
npm run build            # Build for production
npm run start            # Start production server
npm run lint             # Run ESLint
npm run type-check       # Run TypeScript check

# Docker Production
docker compose up -d --build                           # Start prod
docker compose down                                    # Stop prod
docker compose ps                                      # List services
docker compose logs -f webapp                          # View logs

# Debugging
docker compose exec webapp sh                          # Shell into container

# Neo4j CLI (from graph_db folder)
cd ../graph_db && docker compose exec neo4j cypher-shell
```

---

## Troubleshooting

### Neo4j Connection Failed

1. Check if Neo4j is running: `cd ../graph_db && docker compose ps`
2. Verify credentials in `.env.local` match those in `../graph_db/.env`
3. Check Neo4j logs: `cd ../graph_db && docker compose logs neo4j`

### Build Fails with Memory Error

Increase Node.js memory limit:
```bash
NODE_OPTIONS="--max-old-space-size=4096" npm run build
```

### Permission Denied Errors (Docker)

The production image runs as non-root user. Ensure mounted volumes have correct permissions.

---

## Security Considerations

- Never commit `.env` or `.env.local` files
- Use AWS Secrets Manager for production credentials
- Enable Neo4j SSL/TLS in production
- Configure proper security groups for AWS deployment
- Implement rate limiting for API endpoints
- Use HTTPS with proper certificates (ALB handles this)
