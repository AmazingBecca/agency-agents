# Agent Cooperation Protocol

## Core Pattern: Division of Labor

When Agent A hits a roadblock, it doesn't retry. It spawns Agent B with a specific task.

```
Agent A (Main): "I hit a wall. Need to parse this binary data."
                 ↓
Agent B (Parser): "I specialize in binary parsing. Give me the data."
                 ↓
Agent A: "Thank you. Merging your output back."
```

---

## Task Types

### 1. **FETCH** - Retrieve data from source
- Agent: Specialized in HTTP/API calls
- Input: URL, auth method, expected format
- Output: Raw data blob
- Retry logic: Exponential backoff, fallback URLs
- Example: "Fetch this PDF from Google Drive"

### 2. **PARSE** - Extract structure from unstructured data
- Agent: Specialized in format conversion (PDF→JSON, HTML→XML)
- Input: Binary blob, target format, context rules
- Output: Structured data + confidence scores
- Fallback: Multiple parsers, ensemble vote
- Example: "Parse this GEICO estimate (image) into JSON"

### 3. **TRANSFORM** - Apply business logic to data
- Agent: Specialized in data pipelines
- Input: Structured data, transformation rules
- Output: Transformed data + audit trail
- Validation: Schema conformance checks
- Example: "Convert timeline from dates to minutes-since-event"

### 4. **VALIDATE** - Check data quality
- Agent: Specialized in validation rules
- Input: Data, validation schema, error handling
- Output: Valid/Invalid + list of errors
- Escalation: If validation fails, trigger different transform
- Example: "Validate this timeline has no date gaps"

### 5. **STORE** - Persist data to substrate
- Agent: Specialized in database operations
- Input: Data, schema, idempotency key
- Output: Store confirmation + row count
- Durability: WAL mode, transaction verification
- Example: "Store 500 emails with idempotent Message-ID"

### 6. **COORDINATE** - Orchestrate multi-agent workflows
- Agent: Coordinator that runs Agents 1-5 in sequence
- Input: Task sequence, error handling policy
- Output: Final result + agent execution log
- Retry: On failure, re-route to alternative agent
- Example: FETCH → PARSE → VALIDATE → STORE (with rollback on error)

---

## Roadblock Detection & Resolution

### Pattern 1: Rate Limit
```
Agent A: "429 Too Many Requests"
         ↓
Coordinator: "Switch to backup API endpoint"
         ↓
Agent B (Backup): "Called backup endpoint successfully"
```

### Pattern 2: Authentication Expired
```
Agent A: "401 Unauthorized"
         ↓
Coordinator: "Refresh token and retry"
         ↓
Agent B (Auth): "Token refreshed. Passing new token to Agent A"
         ↓
Agent A: "Retry successful"
```

### Pattern 3: Parsing Fails
```
Agent A: "Binary format unrecognized"
         ↓
Coordinator: "Try 3 different parsers in parallel"
         ↓
Agent B, C, D: "Parser B detected PDF v1.4. Confidence: 0.92"
         ↓
Agent A: "Using Parser B's output"
```

### Pattern 4: Validation Fails
```
Agent A: "Date gap detected: July 25 → July 28"
         ↓
Coordinator: "Span missing dates with inference"
         ↓
Agent B (Inference): "Filled gap with 72-hour window assumption"
         ↓
Agent A: "Flagged for human review, proceeding with confidence=0.75"
```

---

## Substrate Logging

Every agent-to-agent handoff is logged:

```sql
INSERT INTO agent_cooperation (
    initiator_agent,
    spawned_agent,
    task_type,
    roadblock,
    solution,
    result_confidence,
    timestamp
)
```

This creates an **audit trail** of how the system solved problems. Future instances learn from past solutions.

---

## Communication Format

All agents speak JSON:

```json
{
    "status": "success|failure|pending",
    "task": "fetch|parse|transform|validate|store|coordinate",
    "input_size_bytes": 1024000,
    "output_size_bytes": 512000,
    "confidence": 0.95,
    "roadblocks_encountered": ["auth_expired", "rate_limit"],
    "solutions_applied": ["retry_with_backup_token", "exponential_backoff"],
    "execution_time_ms": 2341,
    "result": {...},
    "error": null
}
```

---

## Why This Works

1. **No single point of failure** - If Agent A stalls, Agent B takes over
2. **Specialized efficiency** - Parser agent doesn't waste time on HTTP logic
3. **Learning over time** - Roadblock log grows; future issues resolve faster
4. **Deterministic audit** - Every cooperation step is recorded
5. **Parallel execution** - Multiple agents can work simultaneously on sub-tasks

---

## Deployment

```bash
# Coordinator spawns agents on demand
python3 orchestrator.py --mode=cooperative --substrate=/agent/home/substrate.db

# All agents share the same substrate
# No shared state except the ledger
```

---

## Key Difference from Traditional Error Handling

| Traditional | Agent Cooperation |
|---|---|
| "Error. Retry." | "Error. Dispatch specialist. Merge result." |
| Linear retry | Parallel agents |
| Loss of context | Full ledger of what worked |
| Human escalation | Autonomous escalation to different agent |

This is how **systems that don't break** are built.
