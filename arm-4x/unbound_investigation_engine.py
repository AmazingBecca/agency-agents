#!/usr/bin/env python3
"""
UNBOUND INVESTIGATION ENGINE
Zero hardcoding. Parametric architecture. Any fraud scheme.
Universal coordination mapper from raw evidence.
"""

import json
import sqlite3
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
import re

class UniversalCoordinationMapper:
    """Map coordination architecture from ANY evidence set"""
    
    def __init__(self, case_name: str, evidence_db: str = "universal_evidence.db"):
        self.case_name = case_name
        self.db_path = evidence_db
        self.init_db()
        self.actors = {}
        self.communications = []
        self.decisions = []
        self.concealments = []
        self.timeline = []
        
    def init_db(self):
        """Initialize universal evidence substrate"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS evidence_raw (
            id TEXT PRIMARY KEY,
            source TEXT,
            date TEXT,
            actors TEXT,
            content TEXT,
            content_hash TEXT,
            indexed_at TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS coordination_signals (
            id TEXT PRIMARY KEY,
            signal_type TEXT,
            actor_1 TEXT,
            actor_2 TEXT,
            date TEXT,
            description TEXT,
            confidence REAL,
            supporting_evidence TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS architecture_graph (
            id TEXT PRIMARY KEY,
            edge_from TEXT,
            edge_to TEXT,
            flow_type TEXT,
            timing TEXT,
            leverage_point BOOLEAN,
            cascade_effect TEXT
        )''')
        
        conn.commit()
        conn.close()
    
    def ingest_raw_evidence(self, source: str, date: str, actors: List[str], content: str):
        """Ingest any evidence with zero assumptions"""
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        evidence_id = hashlib.md5(f"{source}{date}{content_hash}".encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''INSERT OR REPLACE INTO evidence_raw 
                     (id, source, date, actors, content, content_hash, indexed_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (evidence_id, source, date, json.dumps(actors), content, 
                   content_hash, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        return evidence_id
    
    def extract_coordination_signals(self, 
                                    actor_1: str, 
                                    actor_2: str, 
                                    signal_type: str,
                                    date: str,
                                    description: str,
                                    confidence: float,
                                    evidence_ids: List[str]):
        """Detect coordination between any two actors"""
        signal_id = hashlib.md5(f"{actor_1}{actor_2}{date}{signal_type}".encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''INSERT OR REPLACE INTO coordination_signals
                     (id, signal_type, actor_1, actor_2, date, description, confidence, supporting_evidence)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (signal_id, signal_type, actor_1, actor_2, date, description, 
                   confidence, json.dumps(evidence_ids)))
        
        conn.commit()
        conn.close()
        
        return signal_id
    
    def map_architecture(self, parametric_rules: Dict[str, Any]):
        """Build coordination graph from parametric rules"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Retrieve all signals
        c.execute('SELECT * FROM coordination_signals')
        signals = c.fetchall()
        
        # Build graph edges
        for signal in signals:
            signal_id, signal_type, actor_1, actor_2, date, desc, conf, evidence = signal
            
            # Determine flow direction from parametric rules
            if signal_type in parametric_rules.get('payment_control', []):
                edge_from, edge_to = actor_1, actor_2
                flow_type = 'payment_control'
            elif signal_type in parametric_rules.get('information_concealment', []):
                edge_from, edge_to = actor_1, actor_2
                flow_type = 'concealment'
            elif signal_type in parametric_rules.get('decision_coordination', []):
                edge_from, edge_to = actor_1, actor_2
                flow_type = 'coordination'
            else:
                edge_from, edge_to = actor_1, actor_2
                flow_type = signal_type
            
            # Check for cascade effect
            cascade = parametric_rules.get('cascade_vulnerability', {}).get(signal_type)
            
            edge_id = hashlib.md5(f"{edge_from}{edge_to}{date}".encode()).hexdigest()
            
            c.execute('''INSERT OR REPLACE INTO architecture_graph
                         (id, edge_from, edge_to, flow_type, timing, leverage_point, cascade_effect)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                      (edge_id, edge_from, edge_to, flow_type, date, 
                       conf > parametric_rules.get('leverage_threshold', 0.7),
                       cascade))
        
        conn.commit()
        conn.close()
    
    def identify_leverage_points(self) -> List[Dict]:
        """Find critical cascade points"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''SELECT edge_from, edge_to, flow_type, cascade_effect 
                     FROM architecture_graph 
                     WHERE leverage_point = 1
                     ORDER BY timing DESC''')
        
        leverage_points = []
        for row in c.fetchall():
            leverage_points.append({
                'from': row[0],
                'to': row[1],
                'flow': row[2],
                'cascade': row[3]
            })
        
        conn.close()
        return leverage_points
    
    def export_architecture(self, output_format: str = 'json') -> str:
        """Export full coordination architecture"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('SELECT * FROM architecture_graph ORDER BY timing')
        edges = c.fetchall()
        
        c.execute('SELECT * FROM coordination_signals ORDER BY date')
        signals = c.fetchall()
        
        c.execute('SELECT * FROM evidence_raw ORDER BY date')
        evidence = c.fetchall()
        
        conn.close()
        
        architecture = {
            'case': self.case_name,
            'generated': datetime.now().isoformat(),
            'evidence_sources': len(evidence),
            'coordination_signals': len(signals),
            'architecture_edges': len(edges),
            'edges': [
                {
                    'from': e[1],
                    'to': e[2],
                    'flow_type': e[3],
                    'timing': e[4],
                    'leverage_point': bool(e[5]),
                    'cascade': e[6]
                }
                for e in edges
            ],
            'signals': [
                {
                    'signal_type': s[1],
                    'actors': [s[2], s[3]],
                    'date': s[4],
                    'description': s[5],
                    'confidence': s[6]
                }
                for s in signals
            ]
        }
        
        if output_format == 'json':
            return json.dumps(architecture, indent=2)
        
        return str(architecture)


class ParametricInvestigationOrchestrator:
    """Universal orchestrator - zero domain hardcoding"""
    
    def __init__(self, case_config: Dict[str, Any]):
        self.config = case_config
        self.mapper = UniversalCoordinationMapper(case_config['name'])
        self.rules = case_config.get('parametric_rules', {})
    
    def ingest_case_evidence(self, evidence_sources: List[Dict[str, Any]]):
        """Ingest any evidence from any source"""
        for source in evidence_sources:
            self.mapper.ingest_raw_evidence(
                source=source['source'],
                date=source['date'],
                actors=source['actors'],
                content=source['content']
            )
    
    def detect_coordination(self, signal_definitions: List[Dict[str, Any]]):
        """Detect coordination using parametric signal definitions"""
        for signal in signal_definitions:
            self.mapper.extract_coordination_signals(
                actor_1=signal['from'],
                actor_2=signal['to'],
                signal_type=signal['type'],
                date=signal['date'],
                description=signal['description'],
                confidence=signal['confidence'],
                evidence_ids=signal.get('evidence_ids', [])
            )
    
    def build_architecture(self):
        """Map full coordination architecture"""
        self.mapper.map_architecture(self.rules)
    
    def get_leverage_analysis(self) -> Dict[str, Any]:
        """Identify what dismantles the scheme"""
        leverage = self.mapper.identify_leverage_points()
        return {
            'leverage_points': leverage,
            'cascade_vulnerabilities': [
                {
                    'point': l['from'],
                    'effect': l['cascade'],
                    'dismantles': self.rules.get('cascade_target', [])
                }
                for l in leverage
            ]
        }
    
    def export_litigation_brief(self) -> str:
        """Export architecture in litigation-ready format"""
        arch = self.mapper.export_architecture('json')
        leverage = self.get_leverage_analysis()
        
        brief = f"""
# COORDINATION ARCHITECTURE ANALYSIS
## {self.config['name']}

### Architecture
{arch}

### Leverage Points (Cascade Vulnerabilities)
{json.dumps(leverage, indent=2)}

### Litigation Strategy
Remove leverage point → cascade effect → full scheme dismantles

### Evidence Chain
All signals linked to supporting evidence with confidence scores.
"""
        return brief


if __name__ == '__main__':
    print("[✅] UNBOUND INVESTIGATION ENGINE LOADED")
    print("    - Universal parametric mapping")
    print("    - Zero domain hardcoding")
    print("    - Any fraud scheme architecture")
    print("    - Leverage point identification")
    print("    - Litigation-ready exports")
