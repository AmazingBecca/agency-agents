#!/usr/bin/env python3
"""
Quick runner for ARM Orchestrator
"""
import sys
sys.path.insert(0, '/agent/home')

from orchestrator_arm_unified import ARMOrchestrator
from pathlib import Path
import json

# Initialize
orch = ARMOrchestrator("DaCosta_GEICO")
orch.set_investigation_intent("Fraud pattern discovery with autonomous roadblock resolution")

# Run cycle
context = {
    'resources': {
        'Gmail': {'authenticated': True},
        'Google Drive': {'authenticated': True},
    },
    'apis': ['PACER', 'SEC_EDGAR', 'NHTSA'],
    'extraction_tasks': ['Timeline', 'Patterns', 'Coordination']
}

result = orch.run_cycle(context)

# Report
print(f"Cycle {result['cycle_num']}: {result['findings_count']} findings, {len(result['roadblocks'])} roadblocks")
print(f"Bible: {Path(orch.bible.db_path).stat().st_size} bytes")
