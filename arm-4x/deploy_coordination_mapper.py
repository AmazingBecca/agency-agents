#!/usr/bin/env python3
"""
COORDINATION MAPPER DEPLOYMENT
Ingests actual case evidence -> builds architecture -> identifies leverage
"""

import sys
import json
from unbound_investigation_engine import ParametricInvestigationOrchestrator

def deploy_mapper(case_config: dict):
    """Deploy mapper with zero hardcoding - parametric only"""
    
    print(f"\n[🚀] DEPLOYING: {case_config['name']}")
    
    # Initialize orchestrator
    orchestrator = ParametricInvestigationOrchestrator(case_config)
    
    # Ingest evidence
    print(f"[📥] Ingesting {len(case_config['evidence'])} evidence sources...")
    orchestrator.ingest_case_evidence(case_config['evidence'])
    
    # Detect coordination signals
    print(f"[🔗] Detecting {len(case_config['signals'])} coordination signals...")
    orchestrator.detect_coordination(case_config['signals'])
    
    # Build architecture
    print(f"[🏗️] Building coordination architecture...")
    orchestrator.build_architecture()
    
    # Get leverage analysis
    print(f"[⚡] Identifying leverage points...")
    leverage = orchestrator.get_leverage_analysis()
    
    # Export
    print(f"[📄] Generating litigation brief...")
    brief = orchestrator.export_litigation_brief()
    
    # Output
    print("\n" + "="*80)
    print(brief)
    print("="*80)
    
    return {
        'case': case_config['name'],
        'architecture': json.loads(orchestrator.mapper.export_architecture('json')),
        'leverage': leverage,
        'brief': brief
    }


if __name__ == '__main__':
    # Example: Load parametric config from JSON file
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
        with open(config_file, 'r') as f:
            config = json.load(f)
        result = deploy_mapper(config)
    else:
        print("[⚠️] Usage: python deploy_coordination_mapper.py <config.json>")
        print("\nConfig format:")
        print(json.dumps({
            "name": "Case Name",
            "parametric_rules": {
                "payment_control": ["signal_type1", "signal_type2"],
                "information_concealment": ["signal_type3"],
                "decision_coordination": ["signal_type4"],
                "leverage_threshold": 0.7,
                "cascade_vulnerability": {},
                "cascade_target": []
            },
            "evidence": [
                {
                    "source": "gmail|document|reddit|other",
                    "date": "YYYY-MM-DD",
                    "actors": ["actor1", "actor2"],
                    "content": "raw evidence content"
                }
            ],
            "signals": [
                {
                    "from": "actor1",
                    "to": "actor2",
                    "type": "signal_type",
                    "date": "YYYY-MM-DD",
                    "description": "what happened",
                    "confidence": 0.85,
                    "evidence_ids": ["evidence_id"]
                }
            ]
        }, indent=2))
