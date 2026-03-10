# Intent → Architect → Metadata → VM → SQL → Mesh Pipeline

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  ┌──────────┐   ┌───────────┐   ┌──────────┐   ┌─────────┐   ┌───────┐ │
│  │  INTENT  │ → │ ARCHITECT │ → │ METADATA │ → │   VM    │ → │  SQL  │ │
│  │  (User)  │   │(Reasoning)│   │(Blueprint)│   │(Execute)│   │(State)│ │
│  └──────────┘   └───────────┘   └──────────┘   └─────────┘   └───────┘ │
│       │                                                           │     │
│       │                      ┌────────┐                           │     │
│       └──────────────────────│  MESH  │←──────────────────────────┘     │
│                              │(Replic)│                                 │
│                              └────────┘                                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Layer 1: INTENT (User Input)

**Purpose:** Capture user goal/request

**Tools:**
| Input Method | Tool | Trigger |
|--------------|------|---------|
| Chat message | Direct | Immediate |
| Email | `setup_gmail_trigger` | On new message |
| Webhook | `setup_webhook_trigger` | On POST request |
| Schedule | `setup_schedule_trigger` | Cron/interval |
| File drop | `setup_rss_trigger` | On feed update |

**Output:** Raw intent string + context

**Example:**
```json
{
  "intent": "Find all emails from Karen about water permits",
  "source": "gmail_trigger",
  "timestamp": "2026-01-24T21:54:00Z",
  "context": {
    "thread_id": "18d5a7c3b2e1f9a0",
    "from": "karen@karentraviss.com",
    "subject": "Water permit evidence"
  }
}
```

---

## Layer 2: ARCHITECT (Reasoning)

**Purpose:** Decompose intent into executable plan

**Tool:** `conn_4yf09mc4d2abe99sjs98__remote_http_call` (Gemini API)

**Endpoint:** `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent`

**Input:** Intent JSON + available tools schema

**Output:** Structured execution plan

**Example Request:**
```json
{
  "contents": [{
    "parts": [{
      "text": "You are an execution planner. Given this intent, create a step-by-step plan using available tools.\n\nINTENT: Find all emails from Karen about water permits\n\nAVAILABLE TOOLS:\n- gmail_search_threads(query, readMask)\n- gmail_download_attachment(messageId, filename)\n- google_drive_upload_file(filePath)\n- run_agent_memory_sql(query)\n\nOutput JSON plan with steps."
    }]
  }],
  "generationConfig": {
    "responseMimeType": "application/json"
  }
}
```

**Example Output:**
```json
{
  "plan_id": "plan_20260124_215400",
  "steps": [
    {
      "step": 1,
      "tool": "gmail_search_threads",
      "params": {
        "query": "from:karen@karentraviss.com water permit",
        "readMask": ["date", "participants", "subject", "bodyFull", "attachments"]
      },
      "output_var": "search_results"
    },
    {
      "step": 2,
      "tool": "gmail_download_attachment",
      "condition": "if search_results.attachments.length > 0",
      "params": {
        "messageId": "${search_results.messages[0].id}",
        "filename": "${search_results.attachments[0].filename}"
      },
      "output_var": "downloaded_file"
    },
    {
      "step": 3,
      "tool": "run_agent_memory_sql",
      "params": {
        "query": "INSERT INTO case_findings (source, content, extracted_date) VALUES ('gmail', '${search_results.summary}', NOW())"
      }
    }
  ]
}
```

---

## Layer 3: METADATA (Blueprint)

**Purpose:** Store structured plan for execution + audit trail

**Tool:** `write_file` to `/agent/home/blueprints/`

**Schema:**
```json
{
  "blueprint_id": "string",
  "created": "ISO8601",
  "intent": "string",
  "plan": {
    "steps": [
      {
        "step": "number",
        "tool": "string",
        "params": "object",
        "condition": "string (optional)",
        "output_var": "string",
        "timeout": "number (seconds)",
        "retry": "number (max attempts)"
      }
    ]
  },
  "state": "pending|running|completed|failed",
  "execution_log": [],
  "output": {}
}
```

**Storage Locations:**
| Type | Path |
|------|------|
| Blueprint JSON | `/agent/home/blueprints/{blueprint_id}.json` |
| Execution logs | `/agent/home/logs/{blueprint_id}_exec.log` |
| Output artifacts | `/agent/home/output/{blueprint_id}/` |

---

## Layer 4: VM SANDBOX (Execution)

**Purpose:** Execute each step in isolated environment

**Tool:** `run_command`

**Environment:**
- Alpine Linux v3.23
- Python 3.12 (via uv)
- Network access enabled
- Filesystem: `/agent/` (persistent), `/tmp/` (ephemeral)

**Executor Script:**
```python
#!/usr/bin/env python3
"""Blueprint executor - runs in VM sandbox"""
import json
import subprocess
import sys

def execute_blueprint(blueprint_path):
    with open(blueprint_path) as f:
        blueprint = json.load(f)
    
    context = {}  # Store output variables
    
    for step in blueprint['plan']['steps']:
        # Check condition
        if 'condition' in step:
            if not eval(step['condition'], {"__builtins__": {}}, context):
                continue
        
        # Execute tool
        tool = step['tool']
        params = step['params']
        
        # Substitute variables
        params_str = json.dumps(params)
        for var, value in context.items():
            params_str = params_str.replace(f'${{{var}}}', str(value))
        params = json.loads(params_str)
        
        # Call tool (via agent filesystem interface)
        result = call_tool(tool, params)
        
        # Store output
        if 'output_var' in step:
            context[step['output_var']] = result
        
        # Log execution
        log_step(blueprint['blueprint_id'], step['step'], result)
    
    return context

def call_tool(tool_name, params):
    """Interface to agent tools via filesystem"""
    # Write request
    with open(f'/agent/home/tool_requests/{tool_name}.json', 'w') as f:
        json.dump(params, f)
    
    # Tool execution happens externally
    # Read response
    with open(f'/agent/home/tool_responses/{tool_name}.json') as f:
        return json.load(f)

def log_step(blueprint_id, step_num, result):
    """Log execution to file"""
    with open(f'/agent/home/logs/{blueprint_id}_exec.log', 'a') as f:
        f.write(f"Step {step_num}: {json.dumps(result)}\n")

if __name__ == '__main__':
    execute_blueprint(sys.argv[1])
```

---

## Layer 5: SQL (Feedback/State)

**Purpose:** Persist state, track progress, enable queries

**Tool:** `run_agent_memory_sql`

**Schema:**
```sql
-- Blueprints table
CREATE TABLE blueprints (
    id TEXT PRIMARY KEY,
    intent TEXT NOT NULL,
    plan JSON NOT NULL,
    state TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    error TEXT
);

-- Execution steps table
CREATE TABLE execution_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    blueprint_id TEXT REFERENCES blueprints(id),
    step_num INTEGER,
    tool TEXT,
    params JSON,
    result JSON,
    status TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_ms INTEGER
);

-- Case findings table (your existing)
CREATE TABLE case_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT,
    source TEXT,
    content TEXT,
    extracted_date TIMESTAMP,
    relevance_score REAL,
    processed BOOLEAN DEFAULT FALSE
);

-- Processing log table
CREATE TABLE processing_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    blueprint_id TEXT,
    event TEXT,
    details JSON,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_blueprints_state ON blueprints(state);
CREATE INDEX idx_steps_blueprint ON execution_steps(blueprint_id);
CREATE INDEX idx_findings_case ON case_findings(case_id);
```

**Feedback Queries:**
```sql
-- Get pending blueprints
SELECT * FROM blueprints WHERE state = 'pending' ORDER BY created_at;

-- Get failed steps for retry
SELECT * FROM execution_steps WHERE status = 'failed' AND blueprint_id = ?;

-- Get case findings summary
SELECT case_id, COUNT(*) as findings, MAX(extracted_date) as latest
FROM case_findings GROUP BY case_id;

-- Track execution duration
SELECT blueprint_id, SUM(duration_ms) as total_ms
FROM execution_steps GROUP BY blueprint_id;
```

---

## Layer 6: MESH (Replication)

**Purpose:** Distribute results, enable parallel processing, backup

**Tools:**
| Function | Tool |
|----------|------|
| Cloud backup | `google_drive_upload_file` |
| Parallel execution | `run_subagent` |
| External notification | `send_message` |
| Cross-system sync | `conn_wzy9symrex1ks5aczeeh` (Shortwave) |

**Replication Targets:**
```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Agent     │     │   Google     │     │  Shortwave  │
│  Filesystem │ ──→ │    Drive     │ ──→ │   (Email)   │
│  /agent/    │     │ becca@...    │     │  Comments   │
└─────────────┘     └──────────────┘     └─────────────┘
       │                   │                    │
       │                   │                    │
       ▼                   ▼                    ▼
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│    SQL      │     │  Subagents   │     │   User      │
│  Database   │ ←── │  (Parallel)  │ ──→ │   Email     │
│  (State)    │     │              │     │ Notification│
└─────────────┘     └──────────────┘     └─────────────┘
```

**Subagent Distribution:**
```python
# Parent agent distributes work to subagents
subagents = [
    "/agent/subagents/email_processor.md",
    "/agent/subagents/document_analyzer.md", 
    "/agent/subagents/evidence_extractor.md"
]

# Each subagent handles portion of work
# Results written to shared SQL database
# Parent aggregates final output
```

**Sync Script:**
```python
#!/usr/bin/env python3
"""Mesh replication - sync state to external systems"""
import json
import os

def sync_to_drive(local_path, drive_folder):
    """Upload to Google Drive"""
    # Tool: google_drive_upload_file
    pass

def sync_to_shortwave(thread_id, comment):
    """Add comment to email thread"""
    # Tool: shortwave_create_comment
    pass

def notify_user(message):
    """Send email/text notification"""
    # Tool: send_message
    pass

def replicate_state():
    """Full state replication"""
    # 1. Upload blueprints to Drive
    for f in os.listdir('/agent/home/blueprints/'):
        sync_to_drive(f'/agent/home/blueprints/{f}', 'Blueprints')
    
    # 2. Upload outputs to Drive
    for f in os.listdir('/agent/home/output/'):
        sync_to_drive(f'/agent/home/output/{f}', 'Outputs')
    
    # 3. Notify user of completion
    notify_user("Pipeline completed - results synced to Drive")
```

---

## Complete Pipeline Example

**Scenario:** User emails "Find water permit evidence for January 27 hearing"

```
1. INTENT
   └── Gmail trigger fires
   └── Thread ID: 18d5a7c3b2e1f9a0
   └── Intent: "Find water permit evidence for January 27 hearing"

2. ARCHITECT
   └── Gemini API call
   └── Input: Intent + tool schema
   └── Output: 5-step execution plan

3. METADATA
   └── Blueprint saved: /agent/home/blueprints/bp_20260124_water_permits.json
   └── State: pending

4. VM SANDBOX
   └── Step 1: gmail_search_threads(query="water permit")
   └── Step 2: gmail_download_attachment(messageId, filename)
   └── Step 3: gemini_analyze(file_content)
   └── Step 4: google_drive_upload_file(analysis)
   └── Step 5: run_agent_memory_sql(INSERT INTO case_findings...)

5. SQL
   └── Blueprint state: completed
   └── 3 findings inserted
   └── Execution time: 45 seconds

6. MESH
   └── Analysis uploaded to Drive
   └── Comment added to Shortwave thread
   └── Email sent to user: "Found 3 water permit documents"
   └── Subagent triggered for related searches
```

---

## Anchors (Reference Points)

| Layer | Anchor | Value |
|-------|--------|-------|
| Intent | Gmail connection | conn_dz9f47erg2zqwpkjgken |
| Intent | Webhook trigger | (create with setup_webhook_trigger) |
| Architect | Gemini API | conn_4yf09mc4d2abe99sjs98 |
| Architect | Model | gemini-2.0-flash |
| Metadata | Blueprint path | /agent/home/blueprints/ |
| Metadata | Log path | /agent/home/logs/ |
| VM | Sandbox | Alpine Linux v3.23 |
| VM | Python | 3.12 (via uv) |
| SQL | Database | run_agent_memory_sql |
| SQL | Tables | blueprints, execution_steps, case_findings, processing_log |
| Mesh | Drive | conn_v6zaz8hw00j3kjfby3j8 |
| Mesh | Shortwave | conn_wzy9symrex1ks5aczeeh |
| Mesh | Subagents | /agent/subagents/*.md |

---

## Implementation Status

| Layer | Status | Notes |
|-------|--------|-------|
| Intent | ✅ Ready | Gmail trigger active, webhook available |
| Architect | ✅ Ready | Gemini API connected |
| Metadata | ⚠️ Create | Need to create blueprints/ directory |
| VM | ✅ Ready | Sandbox available |
| SQL | ⚠️ Create | Need to run schema creation |
| Mesh | ✅ Ready | All connections active |

**To deploy full pipeline:**
1. Create blueprint directory structure
2. Run SQL schema creation
3. Test with sample intent
