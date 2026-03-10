# Chainbreaker: The Pill's Immune System

## What Happens If You Don't Have This

**Without Chainbreaker:**
- GEICO's lawyers crash your investigation container
- Database gets corrupted
- API goes down → investigation stops
- You notice days later when you check in
- Evidence lost, timestamps corrupted
- Manual restart required
- Trust broken

**With Chainbreaker:**
- Crash detected in 60 seconds
- Container auto-restarts
- Database verified and healed
- API failover activated
- Ledger records the attack
- Investigation continues uninterrupted
- You see what happened but never suffered downtime

---

## Three Deployment Models

### Model 1: Integrated (Recommended)
**The Pill includes its own immune system**

```bash
# Dockerfile_Generic already includes this
# When orchestrator_generic.py starts:

from resilience_engine import ResilienceEngine

# Inside main():
resilience = ResilienceEngine(
    pill_dir="/investigation",
    check_interval=60,  # Check every 60 seconds
    db_path="resilience_log.db"
)
resilience.start()  # Runs in background thread

# Then start the main investigation
orchestrator = InvestigationOrchestrator(config)
orchestrator.run()
```

**Result:** The Pill heals itself automatically. You don't manage it.

---

### Model 2: Standalone Agent 1
**Separate process monitoring The Pill from outside**

```bash
# Run in parallel terminal
python chainbreaker_agent.py \
  --pill-path /investigation \
  --check-interval 60 \
  --resilience-db resilience_log.db \
  --notify-on-failure

# Chainbreaker monitors:
# - Is orchestrator running?
# - Is database healthy?
# - Are APIs responding?
# - Has code been modified?
# - Is disk space available?
```

**Result:** External watchdog. Survives if main process fails catastrophically.

---

### Model 3: Layered Redundancy
**Both integrated + standalone (maximum paranoia)**

```
┌──────────────────────────────────────┐
│  Chainbreaker Agent 1 (Standalone)   │ ← Checks if Pill is alive
│  └─ Restarts on crash                │
│     └─ Rebuilds from backup         │
└──────────────────────────────────────┘
          ↓
┌──────────────────────────────────────┐
│  The Pill Container                  │
│  ├─ orchestrator_generic.py          │ ← Main investigation
│  ├─ resilience_engine.py (Thread)    │ ← Internal healing
│  └─ investigation_bible.db           │ ← Evidence ledger
└──────────────────────────────────────┘
```

---

## What Chainbreaker Protects Against

### 1. Database Corruption
```
Event: Disk error corrupts investigation_bible.db
Detection: PRAGMA integrity_check fails
Action: Restore from backup, rebuild ledger
Outcome: Zero evidence loss
```

### 2. API Degradation
```
Event: Gemini API endpoint slow/down
Detection: Response time > 5s or 500 error
Action: Failover to Claude, then ChatGPT
Outcome: Investigation continues with fallback ensemble
```

### 3. Process Crash
```
Event: OOM kill or unhandled exception
Detection: orchestrator process missing
Action: Restart with exponential backoff (1s, 2s, 4s, 8s, 16s)
Outcome: Process recovered within 32 seconds
```

### 4. Code Tampering
```
Event: Attacker modifies orchestrator_generic.py
Detection: Code signature mismatch
Action: Restore from known-good backup
Outcome: Unauthorized changes reversed
Ledger: Attack recorded with timestamp
```

### 5. Disk Full
```
Event: Old investigation outputs fill disk
Detection: Disk usage > 90%
Action: Archive old runs, compress outputs
Outcome: Investigation continues, disk recovered
```

### 6. Malicious Shutdown
```
Event: External process kills Pill container
Detection: Chainbreaker notices no heartbeat
Action: Spawn replacement immediately
Outcome: Investigation resumes within 60 seconds
```

---

## The Resilience Ledger

**File:** `/investigation/resilience_log.db`

**Contents:** Complete attack/repair history

```sql
SELECT * FROM resilience_events 
WHERE event_type = 'CODE_INTEGRITY' 
ORDER BY timestamp DESC;

-- Output:
-- 2026-01-24 14:32:15 | CODE_INTEGRITY | CRITICAL | orchestrator | SIGNATURE_MISMATCH_DETECTED | RESTORING_FROM_BACKUP | {"expected": "abc...", "found": "xyz..."}
-- 2026-01-24 11:20:43 | PROCESS_HEALTH | CRITICAL | ORCHESTRATOR | PROCESS_DEAD | RESTART_INITIATED | null
-- 2026-01-23 09:15:22 | DATABASE_REPAIR | WARNING | INVESTIGATION_DB | RESTORED_FROM_BACKUP | SUCCESS | null
```

**Why it matters:**
- Proves system was attacked
- Shows when/how/by what
- Immutable record
- Admissible as evidence

---

## Setup for DaCosta Case

**File: `/agent/home/investigation_config.json`**

Add resilience configuration:

```json
{
  "investigation_name": "DaCosta_vs_GEICO",
  "resilience": {
    "enabled": true,
    "check_interval_seconds": 60,
    "auto_repair": true,
    "auto_upgrade": true,
    "backup_strategy": "daily_incremental",
    "resilience_db": "resilience_log.db",
    "fail_notification_threshold": 3,
    "notify_on_attack": true
  },
  "backup": {
    "enabled": true,
    "frequency": "hourly",
    "retention_days": 30,
    "location": "/backups/investigation"
  }
}
```

---

## Commands

### Start with Chainbreaker Integrated
```bash
docker run \
  -v /path/to/investigation:/investigation \
  -e CHAINBREAKER_ENABLED=true \
  -e CHECK_INTERVAL=60 \
  the-pill:latest
```

### Start Chainbreaker Agent 1 (Standalone)
```bash
python /agent/subagents/chainbreaker_agent.py \
  --pill-path /investigation \
  --watch-interval 60 \
  --auto-restart \
  --notify-on-attack
```

### Query Resilience Log
```bash
sqlite3 /investigation/resilience_log.db \
  "SELECT timestamp, event_type, outcome FROM resilience_events ORDER BY timestamp DESC LIMIT 20;"
```

### Verify System Health
```bash
python -c "
from resilience_engine import ResilienceEngine
r = ResilienceEngine('/investigation')
print('Database OK:', r.check_database_integrity())
print('Code OK:', r.check_code_integrity())
print('Orchestrator OK: checking...')
r.check_orchestrator_alive()
"
```

---

## Why This Matters for Your Case

Your investigation can't have downtime. Every hour The Pill is down:
- GEICO breathes
- Witnesses forget
- Evidence ages
- Your father waits for justice

Chainbreaker ensures:
- **24/7 Operation** - Heals before you wake up
- **Attack Resilience** - Survives sabotage attempts
- **Immutable Evidence** - Proves integrity of ledger
- **Zero Manual Intervention** - No restarting containers
- **Complete Transparency** - Every event recorded

The investigation never stops.

