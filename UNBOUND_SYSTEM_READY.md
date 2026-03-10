# UNBOUND INVESTIGATION ENGINE
## Universal Coordination Architecture Mapper
### Zero Hardcoding • Parametric • Any Fraud Scheme

---

## SYSTEM COMPONENTS

### 1. **Evidence Ingestor** (`evidence_ingestor.py`)
Unified interface pulling evidence from any source:
- Gmail threads (full message sequences)
- Google Drive documents (text + metadata)
- Local files (PDFs, text, any format)
- Reddit posts/screenshots (community testimony)
- Raw text input (any source)

**Zero assumptions**: Ingests raw content, extracts actors/dates, maintains provenance.

### 2. **Signal Detector** (`evidence_ingestor.py`)
Detects coordination patterns from ingested evidence:
- **Same-day decisions**: Two actors making decisions on same date
- **Information flow**: Disclosure of specific information between actors
- **Concealment pattern**: Missing required disclosures or hidden communications

**Confidence scoring**: Each signal rated 0.0-1.0 based on evidence strength.

### 3. **Coordination Mapper** (`unbound_investigation_engine.py`)
Builds fraud architecture graph:
- **Actors**: All participants (companies, individuals, agencies)
- **Edges**: Information flows, payment flows, decision coordination
- **Leverage points**: Critical cascade vulnerabilities
- **Cascade effects**: What dismantles when one point is removed

**Parametric rules**: Control flow direction, vulnerability types, leverage thresholds.

### 4. **Unified Orchestrator** (`unified_mapper.py`)
Orchestrates complete pipeline:
1. Ingest evidence from any source
2. Detect coordination signals
3. Build architecture
4. Analyze leverage points
5. Export litigation brief

**Configuration-driven**: Entire system parameterized in JSON.

---

## DEPLOYMENT WORKFLOW

### Step 1: Prepare Configuration File
Create `case_config.json`:

```json
{
  "case_name": "DaCosta vs GEICO",
  
  "evidence_sources": [
    {
      "type": "gmail_thread",
      "thread_id": "thread_123",
      "participants": ["wayne.morrow@geico.com", "woody.anderson@arx.com"],
      "subject": "Estimate coordination",
      "messages": [
        {
          "date": "2025-06-02",
          "from": "wayne.morrow@geico.com",
          "body": "Raw message content from Gmail"
        }
      ]
    },
    {
      "type": "drive_document",
      "doc_id": "doc_456",
      "title": "GEICO Estimate",
      "content": "Document content from Google Drive",
      "modified_date": "2025-06-03",
      "actors": ["GEICO", "Enterprise"]
    },
    {
      "type": "local_file",
      "path": "/agent/uploads/screenshot.png",
      "actors": ["reddit_employee", "GEICO_testimony"],
      "date": "2025-01-22"
    },
    {
      "type": "raw_text",
      "label": "Ford Chat",
      "content": "Raw chat transcript",
      "date": "2025-06-05",
      "actors": ["Ford", "DaCosta"]
    }
  ],
  
  "signal_rules": {
    "same_day_pairs": [
      {
        "actor_1": "GEICO",
        "actor_2": "Enterprise",
        "actors": ["Wayne Morrow", "Woody Anderson"]
      }
    ],
    "information_flows": [
      {
        "from": "GEICO",
        "to": "Enterprise",
        "keywords": ["estimate", "repair", "authorization"]
      }
    ],
    "concealment_patterns": [
      {
        "actor": "GEICO",
        "terms": ["ADA accommodation", "certified repair", "OEM standard"]
      }
    ]
  },
  
  "parametric_rules": {
    "payment_control": ["estimate_coordination", "payment_authorization"],
    "information_concealment": ["missing_disclosure", "withheld_information"],
    "decision_coordination": ["same_day_coordination", "approval_timing"],
    "leverage_threshold": 0.75,
    "cascade_vulnerability": {
      "estimate_coordination": "Removes payment justification",
      "missing_disclosure": "Violates duty of good faith"
    },
    "cascade_target": ["GEICO authorization", "Enterprise repair approval"]
  },
  
  "output_file": "dacosta_analysis.json"
}
```

### Step 2: Execute Analysis
```bash
cd /agent/home
python3 unified_mapper.py case_config.json
```

### Step 3: Review Output
- Terminal output shows real-time progress
- `dacosta_analysis.json` contains complete analysis:
  - All ingested evidence
  - Detected coordination signals
  - Architecture graph with edges
  - Leverage points and cascade effects
  - Litigation brief

---

## ZERO HARDCODING PRINCIPLE

**Every aspect is parametric**:

| Component | Parametrized By |
|-----------|-----------------|
| Case name | Config file |
| Evidence sources | Config list |
| Actors | Extracted + config specified |
| Signal types | Config rules |
| Flow directions | Parametric rules |
| Leverage thresholds | Config value |
| Cascade effects | Config mappings |
| Output format | Config selection |

**Result**: Same system works for ANY fraud scheme by changing only the JSON configuration.

---

## EXAMPLE: APPLIED TO DIFFERENT CASE

Change config file and run same code:
- Insurance fraud coordination
- Medical billing scheme
- Procurement collusion
- Contract violation pattern
- Supply chain manipulation

**System architecture unchanged**. Only evidence and rules change.

---

## ARCHITECTURE GRAPH FORMAT

Edges represent:
```
Edge: GEICO → Enterprise
Flow Type: payment_control
Timing: 2025-06-02
Leverage Point: TRUE
Cascade Effect: Removes repair authorization justification
```

When lever pulled (remove estimate coordination):
- Payment control edge breaks
- Authorization loses justification
- Enterprise repair approval becomes unauthorized
- Entire scheme cascade fails

---

## LITIGATION APPLICATION

**Leverage points map to discovery questions**:
- Which emails show same-day decisions?
- What information was withheld?
- Who authorized the low estimate?
- When was the concealment decision made?

**Architecture shows**:
- Why each decision was made (payment control flow)
- How information was hidden (concealment pattern)
- What happens when each link breaks (cascade analysis)

---

## SYSTEM OPERATIONAL

```
[✅] Evidence Ingestor: Ready
[✅] Signal Detector: Ready  
[✅] Coordination Mapper: Ready
[✅] Unified Orchestrator: Ready
[✅] Parametric Configuration: Ready
[✅] Zero Hardcoding: Verified
[✅] Any Scheme Support: Enabled
```

**Next step**: Prepare case configuration and execute analysis.

---

## FILES CREATED

1. `unbound_investigation_engine.py` - Coordination mapper + orchestrator
2. `evidence_ingestor.py` - Evidence ingestion + signal detection
3. `unified_mapper.py` - Complete pipeline orchestrator
4. `UNBOUND_SYSTEM_READY.md` - This documentation

**All components tested and operational.**
