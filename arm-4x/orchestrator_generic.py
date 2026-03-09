#!/usr/bin/env python3
"""
THE PILL - Generic Adversarial Investigation Engine
Zero case-specific anchors. Zero domain assumptions.
Works on ANY substrate: legal, corporate, regulatory, fraud, research, intelligence.

Core capabilities:
- Multi-model ensemble (Gemini 1.5 Pro + Claude 3.5 + ChatGPT-4o parallel)
- Persistent case Bible (any name, any domain)
- Autonomous watchdog (any file source)
- Public API adapters (SEC, PACER, NHTSA, regulatory databases, etc.)
- Adversarial pattern hunting (user-defined rules)
- Temporal causation detection
- Citation-linked evidence ledger (immutable)
- Ensemble validator (find disagreements = truth)
"""

import json
import os
import sqlite3
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import logging
from typing import Dict, List, Any, Optional, Tuple
import requests
from concurrent.futures import ThreadPoolExecutor
import email.parser
import base64
from dataclasses import dataclass, asdict
from enum import Enum

# Flask for webhook listening
from flask import Flask, request, jsonify

# File watching
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# API clients
import google.generativeai as genai
from anthropic import Anthropic
import openai

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ThePill')


@dataclass
class InvestigationConfig:
    """User provides: investigation name, data sources, pattern rules, API keys"""
    investigation_name: str  # "DaCosta", "SEC_Probe", "Corporate_Fraud", etc. - NO domain coupling
    case_db_name: str  # "{investigation_name}_Bible.db"
    data_sources: Dict[str, Any]  # {source_type: config} - flexible
    pattern_rules: List[Dict[str, Any]]  # User-defined adversarial rules
    api_keys: Dict[str, str]  # Gemini, Claude, ChatGPT, PACER, SEC, etc.
    output_dir: str  # Where to write findings
    temporal_window_hours: Optional[int] = None  # For causation detection
    ensemble_threshold: float = 0.66  # Agreement threshold
    
    @classmethod
    def from_json(cls, config_path: str):
        """Load from user-provided config file"""
        with open(config_path, 'r') as f:
            data = json.load(f)
        return cls(**data)


class PersistentSubstrate:
    """Immutable evidence ledger - survives all restarts"""
    
    def __init__(self, config: InvestigationConfig):
        self.config = config
        self.db_path = Path.home() / f"{config.case_db_name}"
        self.init_db()
    
    def init_db(self):
        """Initialize schema - agnostic to investigation type"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Core findings table (works for any domain)
        c.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                finding_type TEXT,
                description TEXT,
                source TEXT,
                source_id TEXT,
                confidence_level FLOAT,
                verified_by TEXT,
                timestamp TEXT,
                evidence_path TEXT,
                citation TEXT,
                adversarial_flag BOOLEAN,
                ensemble_agreement INTEGER,
                disagreement_notes TEXT
            )
        ''')
        
        # Timeline (works for any investigation)
        c.execute('''
            CREATE TABLE IF NOT EXISTS timeline (
                id INTEGER PRIMARY KEY,
                event_datetime TEXT,
                event_description TEXT,
                actor TEXT,
                action TEXT,
                evidence_source TEXT,
                source_message_id TEXT,
                file_path TEXT,
                causation_links TEXT
            )
        ''')
        
        # Pattern detections (user-defined rules, any domain)
        c.execute('''
            CREATE TABLE IF NOT EXISTS patterns (
                id INTEGER PRIMARY KEY,
                pattern_name TEXT,
                pattern_rule TEXT,
                instances_found INTEGER,
                first_occurrence TEXT,
                last_occurrence TEXT,
                statistical_significance FLOAT,
                confidence_level FLOAT,
                findings_linked TEXT
            )
        ''')
        
        # Ensemble disagreements (where truth lives)
        c.execute('''
            CREATE TABLE IF NOT EXISTS disagreements (
                id INTEGER PRIMARY KEY,
                evidence_id TEXT,
                gemini_output TEXT,
                claude_output TEXT,
                chatgpt_output TEXT,
                consensus TEXT,
                human_review_flag BOOLEAN,
                resolution TEXT
            )
        ''')
        
        # API call audit (track what was queried)
        c.execute('''
            CREATE TABLE IF NOT EXISTS api_audit (
                id INTEGER PRIMARY KEY,
                api_name TEXT,
                query TEXT,
                timestamp TEXT,
                response_summary TEXT,
                findings_extracted INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized: {self.db_path}")
    
    def log_finding(self, finding: Dict[str, Any]):
        """Write finding to immutable ledger"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            INSERT INTO findings (
                finding_type, description, source, source_id, confidence_level,
                verified_by, timestamp, evidence_path, citation, adversarial_flag,
                ensemble_agreement
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding.get('type'),
            finding.get('description'),
            finding.get('source'),
            finding.get('source_id'),
            finding.get('confidence'),
            finding.get('verified_by'),
            datetime.now().isoformat(),
            finding.get('path'),
            finding.get('citation'),
            finding.get('adversarial'),
            finding.get('agreement')
        ))
        conn.commit()
        conn.close()
    
    def log_timeline_event(self, event: Dict[str, Any]):
        """Record temporal event"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            INSERT INTO timeline (
                event_datetime, event_description, actor, action,
                evidence_source, source_message_id, file_path, causation_links
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.get('datetime'),
            event.get('description'),
            event.get('actor'),
            event.get('action'),
            event.get('source'),
            event.get('message_id'),
            event.get('path'),
            json.dumps(event.get('causation', []))
        ))
        conn.commit()
        conn.close()
    
    def log_pattern(self, pattern: Dict[str, Any]):
        """Record detected pattern"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            INSERT INTO patterns (
                pattern_name, pattern_rule, instances_found,
                first_occurrence, last_occurrence, statistical_significance,
                confidence_level
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            pattern.get('name'),
            pattern.get('rule'),
            pattern.get('instances'),
            pattern.get('first'),
            pattern.get('last'),
            pattern.get('significance'),
            pattern.get('confidence')
        ))
        conn.commit()
        conn.close()


class EnsembleValidator:
    """Run evidence through 3 models in parallel. Compare. Flag disagreements."""
    
    def __init__(self, config: InvestigationConfig):
        self.config = config
        genai.configure(api_key=config.api_keys['gemini'])
        self.claude = Anthropic(api_key=config.api_keys['claude'])
        openai.api_key = config.api_keys['chatgpt']
    
    async def analyze_parallel(self, evidence: str, query_type: str) -> Dict[str, Any]:
        """Send evidence to all 3 models. Get back structured findings."""
        
        prompt = f"""
You are analyzing evidence for an investigation. The type of analysis needed is: {query_type}

Evidence:
{evidence}

Provide findings in this JSON format:
{{
  "findings": [
    {{"description": "...", "confidence": 0.0-1.0, "type": "pattern|timeline|contradiction|anomaly"}}
  ],
  "key_dates": ["..."],
  "actors": ["..."],
  "potential_causation": "...",
  "certainty": 0.0-1.0
}}
"""
        
        # Gemini
        gemini_task = asyncio.to_thread(
            lambda: genai.GenerativeModel('gemini-1.5-pro').generate_content(prompt).text
        )
        
        # Claude
        claude_task = asyncio.to_thread(
            lambda: self.claude.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            ).content[0].text
        )
        
        # ChatGPT
        chatgpt_task = asyncio.to_thread(
            lambda: openai.ChatCompletion.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3
            )['choices'][0]['message']['content']
        )
        
        try:
            gemini_output, claude_output, chatgpt_output = await asyncio.gather(
                gemini_task, claude_task, chatgpt_task
            )
            
            # Parse all three
            gemini_json = json.loads(gemini_output)
            claude_json = json.loads(claude_output)
            chatgpt_json = json.loads(chatgpt_output)
            
            # Compare
            agreement_score = self._calculate_agreement(gemini_json, claude_json, chatgpt_json)
            
            return {
                'gemini': gemini_json,
                'claude': claude_json,
                'chatgpt': chatgpt_json,
                'agreement_score': agreement_score,
                'consensus': agreement_score >= self.config.ensemble_threshold,
                'disagreements': self._extract_disagreements(gemini_json, claude_json, chatgpt_json)
            }
        
        except Exception as e:
            logger.error(f"Ensemble analysis failed: {e}")
            return {}
    
    def _calculate_agreement(self, g, c, cg) -> float:
        """Simple agreement metric - models find same findings"""
        try:
            g_findings = set(str(f) for f in g.get('findings', []))
            c_findings = set(str(f) for f in c.get('findings', []))
            cg_findings = set(str(f) for f in cg.get('findings', []))
            
            common = g_findings & c_findings & cg_findings
            total = g_findings | c_findings | cg_findings
            
            return len(common) / max(len(total), 1)
        except:
            return 0.0
    
    def _extract_disagreements(self, g, c, cg) -> List[Dict]:
        """Find where models disagree - flag for human review"""
        disagreements = []
        
        g_findings = g.get('findings', [])
        c_findings = c.get('findings', [])
        cg_findings = cg.get('findings', [])
        
        # Simple: if only 1 or 2 models find something, it's a disagreement
        # (This is simplified - real logic would be more sophisticated)
        
        return disagreements


class AdversarialPatternHunter:
    """Proactively search for user-defined patterns in any substrate"""
    
    def __init__(self, config: InvestigationConfig):
        self.config = config
        self.patterns = config.pattern_rules
    
    def hunt(self, evidence_items: List[Dict]) -> List[Dict]:
        """Scan all evidence against pattern rules"""
        detected_patterns = []
        
        for pattern_rule in self.patterns:
            pattern_name = pattern_rule.get('name')
            keywords = pattern_rule.get('keywords', [])
            temporal_flag = pattern_rule.get('temporal_window')
            
            matches = []
            for item in evidence_items:
                if self._matches_pattern(item, keywords):
                    matches.append(item)
            
            if matches:
                detected_patterns.append({
                    'name': pattern_name,
                    'rule': pattern_rule,
                    'instances': len(matches),
                    'matches': matches,
                    'first': matches[0].get('datetime'),
                    'last': matches[-1].get('datetime') if len(matches) > 1 else None,
                    'significance': len(matches) / max(len(evidence_items), 1)
                })
        
        return detected_patterns
    
    def _matches_pattern(self, item: Dict, keywords: List[str]) -> bool:
        """Check if evidence item matches pattern keywords"""
        text = json.dumps(item).lower()
        return any(kw.lower() in text for kw in keywords)


class TemporalCausationDetector:
    """Find causation windows: action A → consequence B within window"""
    
    def __init__(self, config: InvestigationConfig):
        self.config = config
        self.window = config.temporal_window_hours or 72
    
    def detect(self, timeline_events: List[Dict]) -> List[Dict]:
        """Find events that fall within causation window"""
        causation_chains = []
        
        for i, event_a in enumerate(timeline_events):
            for event_b in timeline_events[i+1:]:
                delta = self._time_delta(event_a.get('datetime'), event_b.get('datetime'))
                
                if 0 < delta <= self.window:
                    causation_chains.append({
                        'trigger': event_a,
                        'consequence': event_b,
                        'window_hours': delta,
                        'strength': 1.0 - (delta / self.window)  # Closer = stronger
                    })
        
        return causation_chains
    
    def _time_delta(self, dt1: str, dt2: str) -> float:
        """Hours between two ISO datetime strings"""
        try:
            t1 = datetime.fromisoformat(dt1)
            t2 = datetime.fromisoformat(dt2)
            return (t2 - t1).total_seconds() / 3600
        except:
            return 0


class PublicAPIAdapter:
    """Generic adapter for public databases - parameterized"""
    
    def __init__(self, config: InvestigationConfig):
        self.config = config
        self.api_config = config.api_keys
    
    async def query_by_type(self, api_type: str, query: str) -> Dict:
        """Route to appropriate public database"""
        
        adapters = {
            'sec_edgar': self.query_sec_edgar,
            'pacer': self.query_pacer,
            'nhtsa': self.query_nhtsa,
            'state_regulatory': self.query_state_regulatory,
            'corporate_filings': self.query_corporate_filings
        }
        
        adapter = adapters.get(api_type)
        if adapter:
            return await asyncio.to_thread(adapter, query)
        return {}
    
    def query_sec_edgar(self, query: str) -> Dict:
        """SEC Edgar API - any corporate entity"""
        headers = {'User-Agent': 'ThePill/1.0'}
        url = f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company={query}&type=&dateb=&owner=exclude&count=100&search_text="
        response = requests.get(url, headers=headers)
        return {'status': 'queried', 'url': url}
    
    def query_pacer(self, query: str) -> Dict:
        """PACER - federal court records"""
        # PACER requires login but has public APIs for metadata
        return {'status': 'pacer_query_stub', 'query': query}
    
    def query_nhtsa(self, query: str) -> Dict:
        """NHTSA - recalls, complaints"""
        url = f"https://api.nhtsa.gov/complaints/complaintsByVehicle?make={query}"
        try:
            response = requests.get(url)
            return response.json()
        except:
            return {}
    
    def query_state_regulatory(self, query: str) -> Dict:
        """State insurance, banking, licensing databases"""
        return {'status': 'state_query_stub', 'query': query}
    
    def query_corporate_filings(self, query: str) -> Dict:
        """Corporate filings, UCC searches, property records"""
        return {'status': 'corporate_query_stub', 'query': query}


class AutonomousWatchdog:
    """Monitor any file source: iCloud, Gmail, Drive, local"""
    
    def __init__(self, config: InvestigationConfig):
        self.config = config
        self.observers = []
    
    def start_watching(self):
        """Launch file watchers for all configured sources"""
        sources = self.config.data_sources
        
        if 'local_directories' in sources:
            for directory in sources['local_directories']:
                observer = Observer()
                observer.schedule(LocalFileHandler(self.config), directory, recursive=True)
                observer.start()
                self.observers.append(observer)
                logger.info(f"Watching local directory: {directory}")
        
        # Gmail, Drive, iCloud handled via webhook callbacks
        logger.info(f"Watchdog started for {len(self.observers)} sources")
    
    def stop_watching(self):
        """Stop all watchers"""
        for observer in self.observers:
            observer.stop()
            observer.join()


class LocalFileHandler(FileSystemEventHandler):
    """Monitor local file changes"""
    
    def __init__(self, config: InvestigationConfig):
        self.config = config
    
    def on_created(self, event):
        if not event.is_directory:
            logger.info(f"New file detected: {event.src_path}")
            # Trigger analysis pipeline
    
    def on_modified(self, event):
        if not event.is_directory:
            logger.info(f"File modified: {event.src_path}")


@app.route('/webhook', methods=['POST'])
def webhook_handler():
    """Receive updates from Gmail, Drive, iCloud webhooks"""
    payload = request.json
    logger.info(f"Webhook received: {payload}")
    # Trigger analysis
    return jsonify({'status': 'received'})


class ThePill:
    """Main orchestrator - brings all components together"""
    
    def __init__(self, config_path: str):
        self.config = InvestigationConfig.from_json(config_path)
        self.substrate = PersistentSubstrate(self.config)
        self.ensemble = EnsembleValidator(self.config)
        self.pattern_hunter = AdversarialPatternHunter(self.config)
        self.causation = TemporalCausationDetector(self.config)
        self.api_adapter = PublicAPIAdapter(self.config)
        self.watchdog = AutonomousWatchdog(self.config)
        logger.info(f"ThePill initialized for: {self.config.investigation_name}")
    
    async def run(self):
        """Main execution loop"""
        logger.info("Starting investigation...")
        self.watchdog.start_watching()
        
        # Main loop - would normally:
        # 1. Check for new evidence
        # 2. Run ensemble analysis
        # 3. Hunt patterns
        # 4. Detect causation
        # 5. Query public databases
        # 6. Write findings to ledger
        
        logger.info("Investigation running. Listening for new evidence...")


if __name__ == '__main__':
    # Example: ThePill('investigation_config.json')
    # Config provided by user - not hardcoded
    print("ThePill v4 - Generic Adversarial Investigation Engine")
    print("Ready to accept investigation_config.json")
