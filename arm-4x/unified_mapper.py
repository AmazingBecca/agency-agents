#!/usr/bin/env python3
"""
UNIFIED INVESTIGATION MAPPER
Orchestrates: Evidence Ingestor → Signal Detector → Coordination Mapper → Leverage Analysis
Zero hardcoding. Parametric configuration. Any case.
"""

import json
import sys
import os
from typing import Dict, List, Any
from datetime import datetime

from evidence_ingestor import EvidenceIngestor, SignalDetector
from unbound_investigation_engine import ParametricInvestigationOrchestrator


class UnifiedInvestigationMapper:
    """Complete orchestration pipeline"""
    
    def __init__(self, case_name: str):
        self.case_name = case_name
        self.ingestor = EvidenceIngestor()
        self.detector = None
        self.orchestrator = None
        self.results = {}
    
    def ingest_evidence(self, evidence_sources: List[Dict[str, Any]]):
        """Ingest all evidence from any source"""
        print(f"\n[📥] INGESTING EVIDENCE")
        print(f"    {len(evidence_sources)} sources")
        
        for source in evidence_sources:
            source_type = source.get('type')
            
            if source_type == 'gmail_thread':
                self.ingestor.from_gmail_thread(
                    thread_id=source['thread_id'],
                    participants=source['participants'],
                    subject=source['subject'],
                    messages=source['messages']
                )
            
            elif source_type == 'drive_document':
                self.ingestor.from_google_drive_document(
                    doc_id=source['doc_id'],
                    title=source['title'],
                    content=source['content'],
                    modified_date=source['modified_date'],
                    relevant_actors=source['actors']
                )
            
            elif source_type == 'local_file':
                self.ingestor.from_local_file(
                    file_path=source['path'],
                    actors=source['actors'],
                    date=source.get('date')
                )
            
            elif source_type == 'reddit_screenshots':
                self.ingestor.from_reddit_screenshots(
                    screenshots=source['paths'],
                    date=source['date'],
                    context=source['context']
                )
            
            elif source_type == 'raw_text':
                self.ingestor.from_raw_text(
                    text=source['content'],
                    source_label=source['label'],
                    date=source['date'],
                    actors=source['actors']
                )
        
        stats = self.ingestor.get_statistics()
        print(f"    ✅ Ingested {stats['total_evidence']} evidence items")
        print(f"    ✅ Found {len(stats['unique_actors'])} unique actors")
        print(f"    ✅ Date range: {stats['date_range']['earliest']} to {stats['date_range']['latest']}")
    
    def detect_signals(self, signal_rules: Dict[str, Any]):
        """Detect coordination signals from ingested evidence"""
        print(f"\n[🔗] DETECTING COORDINATION SIGNALS")
        
        self.detector = SignalDetector(self.ingestor.evidence)
        
        # Same-day decisions
        if 'same_day_pairs' in signal_rules:
            for pair in signal_rules['same_day_pairs']:
                self.detector.detect_same_day_decisions(
                    actor_1=pair['actor_1'],
                    actor_2=pair['actor_2'],
                    actors_to_find=pair.get('actors', [pair['actor_1'], pair['actor_2']])
                )
        
        # Information flows
        if 'information_flows' in signal_rules:
            for flow in signal_rules['information_flows']:
                self.detector.detect_information_flow(
                    from_actor=flow['from'],
                    to_actor=flow['to'],
                    keywords=flow['keywords']
                )
        
        # Concealment patterns
        if 'concealment_patterns' in signal_rules:
            for pattern in signal_rules['concealment_patterns']:
                self.detector.detect_concealment_pattern(
                    actor=pattern['actor'],
                    concealed_terms=pattern['terms']
                )
        
        signals = self.detector.get_all_signals()
        print(f"    ✅ Detected {len(signals)} coordination signals")
        
        return signals
    
    def build_architecture(self, parametric_rules: Dict[str, Any]):
        """Build coordination architecture"""
        print(f"\n[🏗️] BUILDING COORDINATION ARCHITECTURE")
        
        case_config = {
            'name': self.case_name,
            'parametric_rules': parametric_rules,
            'evidence': self.ingestor.evidence,
            'signals': self.detector.get_all_signals()
        }
        
        self.orchestrator = ParametricInvestigationOrchestrator(case_config)
        self.orchestrator.ingest_case_evidence(self.ingestor.evidence)
        self.orchestrator.detect_coordination(self.detector.get_all_signals())
        self.orchestrator.build_architecture()
        
        print(f"    ✅ Architecture mapped")
    
    def analyze_leverage(self) -> Dict[str, Any]:
        """Identify leverage points and cascade vulnerabilities"""
        print(f"\n[⚡] ANALYZING LEVERAGE POINTS")
        
        leverage = self.orchestrator.get_leverage_analysis()
        
        print(f"    ✅ Found {len(leverage['leverage_points'])} critical points")
        for point in leverage['leverage_points']:
            print(f"       • {point['from']} → {point['to']}: {point['flow']}")
        
        self.results['leverage'] = leverage
        return leverage
    
    def export_brief(self) -> str:
        """Export litigation-ready brief"""
        print(f"\n[📄] GENERATING LITIGATION BRIEF")
        
        brief = self.orchestrator.export_litigation_brief()
        self.results['brief'] = brief
        
        return brief
    
    def export_full_analysis(self, output_file: str = None) -> Dict[str, Any]:
        """Export complete analysis"""
        analysis = {
            'case': self.case_name,
            'generated': datetime.now().isoformat(),
            'statistics': self.ingestor.get_statistics(),
            'evidence': self.ingestor.evidence,
            'signals': self.detector.get_all_signals(),
            'architecture': json.loads(self.orchestrator.mapper.export_architecture('json')),
            'leverage': self.results.get('leverage'),
            'brief': self.results.get('brief')
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(analysis, f, indent=2)
            print(f"    ✅ Exported to {output_file}")
        
        return analysis
    
    def run_complete_analysis(self,
                             evidence_sources: List[Dict[str, Any]],
                             signal_rules: Dict[str, Any],
                             parametric_rules: Dict[str, Any],
                             output_file: str = None) -> Dict[str, Any]:
        """Execute complete analysis pipeline"""
        
        print(f"\n{'='*80}")
        print(f"UNIFIED INVESTIGATION MAPPER")
        print(f"Case: {self.case_name}")
        print(f"{'='*80}")
        
        self.ingest_evidence(evidence_sources)
        self.detect_signals(signal_rules)
        self.build_architecture(parametric_rules)
        leverage = self.analyze_leverage()
        self.export_brief()
        
        results = self.export_full_analysis(output_file)
        
        print(f"\n{'='*80}")
        print(f"✅ ANALYSIS COMPLETE")
        print(f"{'='*80}\n")
        
        return results


def run_from_config_file(config_file: str) -> Dict[str, Any]:
    """Load configuration and run analysis"""
    
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    mapper = UnifiedInvestigationMapper(config['case_name'])
    
    return mapper.run_complete_analysis(
        evidence_sources=config['evidence_sources'],
        signal_rules=config['signal_rules'],
        parametric_rules=config['parametric_rules'],
        output_file=config.get('output_file')
    )


if __name__ == '__main__':
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
        run_from_config_file(config_file)
    else:
        print("[⚠️] Usage: python unified_mapper.py <config.json>")
        print("\nExample configuration:")
        example_config = {
            "case_name": "Case Name",
            "evidence_sources": [
                {
                    "type": "gmail_thread",
                    "thread_id": "thread_123",
                    "participants": ["actor1@example.com", "actor2@example.com"],
                    "subject": "Email subject",
                    "messages": [
                        {
                            "date": "2025-06-01",
                            "from": "actor1@example.com",
                            "body": "Message content"
                        }
                    ]
                }
            ],
            "signal_rules": {
                "same_day_pairs": [
                    {
                        "actor_1": "Actor 1",
                        "actor_2": "Actor 2",
                        "actors": ["Actor 1", "Actor 2"]
                    }
                ],
                "information_flows": [
                    {
                        "from": "Actor 1",
                        "to": "Actor 2",
                        "keywords": ["keyword1", "keyword2"]
                    }
                ],
                "concealment_patterns": [
                    {
                        "actor": "Actor",
                        "terms": ["required_disclosure1", "required_disclosure2"]
                    }
                ]
            },
            "parametric_rules": {
                "payment_control": ["signal_type"],
                "information_concealment": ["signal_type"],
                "decision_coordination": ["signal_type"],
                "leverage_threshold": 0.7,
                "cascade_vulnerability": {},
                "cascade_target": []
            },
            "output_file": "analysis_output.json"
        }
        
        print(json.dumps(example_config, indent=2))
