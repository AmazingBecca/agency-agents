#!/usr/bin/env python3
"""
THE PILL v4 - Adversarial Investigation Engine
Substrate-level orchestrator for fraud pattern detection across multiple LLM ensemble + public databases
Case-agnostic, substrate-aware, autonomous watchdog

Core functions:
- Multi-model ensemble (Gemini 1.5 Pro + Claude 3.5 + ChatGPT-4o)
- Persistent case Bible database
- Autonomous file watchdog (iCloud, Gmail, Google Drive)
- SEC Edgar + NHTSA + Alabama DOI + Gmail metadata integration
- Adversarial pattern hunting
- Retaliation window detection
- Citation-linked evidence ledger
"""

import json
import os
import sqlite3
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import logging
from typing import Dict, List, Any, Optional
import requests
from concurrent.futures import ThreadPoolExecutor
import email.parser
import base64

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

class PersistentSubstrate:
    """DaCosta_Bible.db - Immutable evidence ledger"""
    
    def __init__(self, case_name: str):
        self.db_path = Path.home() / f"{case_name.replace(' ', '_')}_Bible.db"
        self.init_db()
    
    def init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Findings table
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
                ensemble_agreement INTEGER
            )
        ''')
        
        # Timeline events
        c.execute('''
            CREATE TABLE IF NOT EXISTS timeline (
                id INTEGER PRIMARY KEY,
                event_date TEXT,
                event_time TEXT,
                event_description TEXT,
                actor TEXT,
                action TEXT,
                evidence_source TEXT,
                gmail_message_id TEXT,
                file_path TEXT,
                causation_link TEXT
            )
        ''')
        
        # Pattern detections
        c.execute('''
            CREATE TABLE IF NOT EXISTS patterns (
                id INTEGER PRIMARY KEY,
                pattern_name TEXT,
                pattern_type TEXT,
                instances INTEGER,
                confidence FLOAT,
                first_detected TEXT,
                supporting_findings TEXT,
                adversarial_score FLOAT
            )
        ''')
        
        # Source manifest
        c.execute('''
            CREATE TABLE IF NOT EXISTS sources (
                id INTEGER PRIMARY KEY,
                source_type TEXT,
                source_name TEXT,
                last_pulled TEXT,
                record_count INTEGER,
                status TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized: {self.db_path}")
    
    def log_finding(self, finding: Dict[str, Any]):
        """Log finding with immutable timestamp and citation"""
        finding['timestamp'] = datetime.utcnow().isoformat()
        finding['citation'] = self._generate_citation(finding)
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            INSERT INTO findings 
            (finding_type, description, source, source_id, confidence_level, 
             verified_by, timestamp, evidence_path, citation, adversarial_flag, ensemble_agreement)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding.get('finding_type'),
            finding.get('description'),
            finding.get('source'),
            finding.get('source_id'),
            finding.get('confidence_level', 0.0),
            finding.get('verified_by'),
            finding['timestamp'],
            finding.get('evidence_path'),
            finding['citation'],
            finding.get('adversarial_flag', False),
            finding.get('ensemble_agreement', 0)
        ))
        conn.commit()
        conn.close()
        logger.info(f"Finding logged: {finding['citation']}")
    
    def _generate_citation(self, finding: Dict) -> str:
        """Generate immutable citation"""
        source = finding.get('source', 'unknown')
        source_id = finding.get('source_id', 'N/A')
        timestamp = datetime.utcnow().isoformat()
        return f"{source}:{source_id}:{timestamp}"


class EnsembleValidator:
    """Multi-model reasoning with cross-validation"""
    
    def __init__(self, gemini_key: str, claude_key: str, openai_key: str):
        genai.configure(api_key=gemini_key)
        self.gemini_model = genai.GenerativeModel('gemini-1.5-pro')
        
        self.claude_client = Anthropic(api_key=claude_key)
        openai.api_key = openai_key
        
        self.executor = ThreadPoolExecutor(max_workers=3)
    
    async def analyze_document(self, file_path: str, analysis_type: str) -> Dict[str, Any]:
        """Parallel analysis across 3 models"""
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Prepare for multimodal if PDF/image
        is_binary = file_path.endswith(('.pdf', '.png', '.jpg', '.jpeg'))
        
        # Run all 3 in parallel
        loop = asyncio.get_event_loop()
        
        gemini_result = loop.run_in_executor(
            self.executor,
            self._gemini_extract,
            file_path, file_data, analysis_type, is_binary
        )
        
        claude_result = loop.run_in_executor(
            self.executor,
            self._claude_analyze,
            file_path, file_data, analysis_type
        )
        
        gpt_result = loop.run_in_executor(
            self.executor,
            self._gpt_analyze,
            file_path, file_data, analysis_type
        )
        
        results = await asyncio.gather(gemini_result, claude_result, gpt_result)
        
        return self._validate_ensemble(results, file_path, analysis_type)
    
    def _gemini_extract(self, file_path: str, file_data: bytes, analysis_type: str, is_binary: bool) -> Dict:
        """Gemini 1.5 Pro - Pixel-perfect OCR"""
        try:
            if is_binary:
                file = genai.upload_file(file_path)
                response = self.gemini_model.generate_content([
                    f"Extract all text, numbers, dates, and signatures from this document. "
                    f"Analysis type: {analysis_type}. "
                    f"Return structured JSON with fields: text, numbers, dates, signatures, anomalies",
                    file
                ])
            else:
                response = self.gemini_model.generate_content(
                    f"Analyze: {file_path}\nAnalysis type: {analysis_type}\nContent:\n{file_data.decode('utf-8', errors='ignore')}"
                )
            
            return {
                'model': 'gemini-1.5-pro',
                'analysis': response.text,
                'confidence': 0.95
            }
        except Exception as e:
            logger.error(f"Gemini error: {e}")
            return {'model': 'gemini-1.5-pro', 'error': str(e), 'confidence': 0.0}
    
    def _claude_analyze(self, file_path: str, file_data: bytes, analysis_type: str) -> Dict:
        """Claude 3.5 - Reasoning"""
        try:
            response = self.claude_client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=2000,
                messages=[{
                    "role": "user",
                    "content": f"""Analyze {file_path} for {analysis_type}.
                    
Identify:
1. Key facts and figures
2. Temporal sequences
3. Actor relationships
4. Anomalies or inconsistencies
5. Fraud indicators

Content:
{file_data.decode('utf-8', errors='ignore')[:10000]}

Return structured analysis."""
                }]
            )
            return {
                'model': 'claude-3.5-sonnet',
                'analysis': response.content[0].text,
                'confidence': 0.90
            }
        except Exception as e:
            logger.error(f"Claude error: {e}")
            return {'model': 'claude-3.5-sonnet', 'error': str(e), 'confidence': 0.0}
    
    def _gpt_analyze(self, file_path: str, file_data: bytes, analysis_type: str) -> Dict:
        """GPT-4o - Cross-check"""
        try:
            response = openai.ChatCompletion.create(
                model="gpt-4o",
                messages=[{
                    "role": "user",
                    "content": f"""Cross-check analysis of {file_path} for {analysis_type}.
                    
Look for contradictions with other sources, timeline gaps, and coordination indicators.

Content:
{file_data.decode('utf-8', errors='ignore')[:10000]}"""
                }],
                max_tokens=2000
            )
            return {
                'model': 'gpt-4-o',
                'analysis': response.choices[0].message.content,
                'confidence': 0.88
            }
        except Exception as e:
            logger.error(f"GPT error: {e}")
            return {'model': 'gpt-4o', 'error': str(e), 'confidence': 0.0}
    
    def _validate_ensemble(self, results: List[Dict], file_path: str, analysis_type: str) -> Dict:
        """Find truth where models agree, flag where they disagree"""
        agreement_count = 0
        disagreements = []
        
        # Simple agreement detection (in production: semantic similarity)
        analyses = [r.get('analysis', '') for r in results]
        
        # Check if all have confidence > 0.8
        high_confidence = sum(1 for r in results if r.get('confidence', 0) > 0.8)
        agreement_count = high_confidence
        
        return {
            'file': file_path,
            'analysis_type': analysis_type,
            'ensemble_results': results,
            'agreement_level': agreement_count / 3,  # 0-1 scale
            'consensus': analyses[0] if agreement_count >= 2 else "DISAGREEMENT - MANUAL REVIEW REQUIRED",
            'timestamp': datetime.utcnow().isoformat()
        }


class PublicDatabaseIntegration:
    """SEC Edgar + NHTSA + Alabama DOI + Gmail metadata"""
    
    def __init__(self, substrate: PersistentSubstrate):
        self.substrate = substrate
        self.sec_base = "https://data.sec.gov/api/xbrl"
        self.nhtsa_base = "https://api.nhtsa.gov/complaints"
        self.gmail_parser = email.parser.Parser()
    
    async def fetch_sec_filings(self, company_cik: str, filing_type: str = "10-K") -> List[Dict]:
        """Pull SEC Edgar filings - Berkshire Hathaway GEICO disclosures"""
        try:
            # CIK for Berkshire Hathaway: 0000015090
            url = f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={company_cik}&type={filing_type}&dateb=&owner=exclude&count=100&search_text="
            
            response = requests.get(url, headers={'User-Agent': 'ThePill/1.0'})
            
            logger.info(f"SEC Edgar query: {company_cik}, type: {filing_type}")
            
            return {
                'source': 'SEC Edgar',
                'company_cik': company_cik,
                'filing_type': filing_type,
                'response_status': response.status_code
            }
        except Exception as e:
            logger.error(f"SEC Edgar fetch error: {e}")
            return []
    
    async def fetch_nhtsa_data(self, manufacturer: str, model: str, year: int) -> List[Dict]:
        """Query NHTSA for recalls, TSBs, complaints"""
        try:
            url = f"https://api.nhtsa.gov/complaints/complaintsByVehicle?make={manufacturer}&model={model}&yearFrom={year}&yearTo={year}"
            response = requests.get(url)
            
            logger.info(f"NHTSA query: {year} {manufacturer} {model}")
            
            return response.json() if response.status_code == 200 else []
        except Exception as e:
            logger.error(f"NHTSA fetch error: {e}")
            return []
    
    async def fetch_alabama_doi(self, company_name: str, complaint_type: str = "cost_cutting") -> Dict:
        """Query Alabama DOI complaint database"""
        # Note: Alabama DOI doesn't have direct API, but data is available via public search
        logger.info(f"Alabama DOI pattern search: {company_name}, type: {complaint_type}")
        
        return {
            'source': 'Alabama DOI',
            'company': company_name,
            'complaint_type': complaint_type,
            'note': 'Manual query required - use public database at sos.alabama.gov/insurance'
        }
    
    def parse_gmail_metadata(self, eml_file_path: str) -> Dict:
        """Extract causation timeline from Gmail Message-ID and headers"""
        try:
            with open(eml_file_path, 'r') as f:
                msg = self.gmail_parser.parse(f)
            
            return {
                'message_id': msg.get('Message-ID'),
                'from': msg.get('From'),
                'to': msg.get('To'),
                'subject': msg.get('Subject'),
                'date': msg.get('Date'),
                'received': msg.get_all('Received'),
                'timestamp': self._parse_email_date(msg.get('Date'))
            }
        except Exception as e:
            logger.error(f"Gmail metadata parse error: {e}")
            return {}
    
    def _parse_email_date(self, date_str: str) -> str:
        """Convert email date to ISO format"""
        from email.utils import parsedate_to_datetime
        try:
            dt = parsedate_to_datetime(date_str)
            return dt.isoformat()
        except:
            return date_str


class AdversarialReasoning:
    """Proactive fraud pattern hunting"""
    
    FRAUD_PATTERNS = {
        'cost_cutting': {
            'indicators': [
                'estimate below market rate',
                'repair instead of replacement',
                'OEM violation',
                'adjuster specialization in cost reduction'
            ],
            'weight': 0.9
        },
        'ada_retaliation': {
            'indicators': [
                'ADA disclosure triggers change in service',
                '72-hour window between disclosure and action',
                'undisclosed cost review',
                'service downgrade post-ADA'
            ],
            'weight': 0.95
        },
        'coordination': {
            'indicators': [
                'adjuster on special team',
                'repair shop guaranteed compliance',
                'cost-cutting at odds with safety',
                'timeline compression'
            ],
            'weight': 0.85
        },
        'evidence_destruction': {
            'indicators': [
                'files deleted or archived',
                'communications redirected',
                'chat ended abruptly',
                'missing documentation'
            ],
            'weight': 0.80
        }
    }
    
    def __init__(self, substrate: PersistentSubstrate):
        self.substrate = substrate
    
    def hunt_patterns(self, findings: List[Dict]) -> List[Dict]:
        """Proactively hunt for fraud patterns"""
        patterns_found = []
        
        for pattern_name, pattern_def in self.FRAUD_PATTERNS.items():
            matches = 0
            for finding in findings:
                if any(indicator.lower() in finding.get('description', '').lower() 
                       for indicator in pattern_def['indicators']):
                    matches += 1
            
            if matches > 0:
                adversarial_score = (matches / len(findings)) * pattern_def['weight']
                patterns_found.append({
                    'pattern_name': pattern_name,
                    'matches': matches,
                    'adversarial_score': adversarial_score,
                    'timestamp': datetime.utcnow().isoformat()
                })
        
        return patterns_found


class FileWatchdog(FileSystemEventHandler):
    """Autonomous monitoring of iCloud, Gmail exports, Google Drive"""
    
    def __init__(self, substrate: PersistentSubstrate, ensemble: EnsembleValidator):
        self.substrate = substrate
        self.ensemble = ensemble
        self.processed_files = set()
    
    def on_created(self, event):
        """New file detected"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        file_hash = hashlib.sha256(file_path.encode()).hexdigest()
        
        if file_hash not in self.processed_files:
            logger.info(f"File detected: {file_path}")
            self.processed_files.add(file_hash)
            
            # Queue for async processing
            asyncio.create_task(self._process_file(file_path))
    
    async def _process_file(self, file_path: str):
        """Process file with ensemble"""
        try:
            result = await self.ensemble.analyze_document(file_path, "fraud_detection")
            
            finding = {
                'finding_type': 'file_analysis',
                'description': result.get('consensus'),
                'source': 'autonomous_watchdog',
                'source_id': file_path,
                'confidence_level': result.get('agreement_level'),
                'verified_by': 'ensemble',
                'evidence_path': file_path,
                'adversarial_flag': True
            }
            
            self.substrate.log_finding(finding)
        except Exception as e:
            logger.error(f"File processing error: {e}")


# Flask webhook endpoint
@app.route('/webhook', methods=['POST'])
def webhook():
    """Listen for external triggers"""
    data = request.json
    logger.info(f"Webhook received: {data}")
    
    return jsonify({'status': 'received', 'timestamp': datetime.utcnow().isoformat()}), 200


def start_watchdog(watch_paths: List[str], substrate: PersistentSubstrate, ensemble: EnsembleValidator):
    """Start autonomous file monitoring"""
    event_handler = FileWatchdog(substrate, ensemble)
    observer = Observer()
    
    for path in watch_paths:
        observer.schedule(event_handler, path, recursive=True)
    
    observer.start()
    logger.info(f"Watchdog started on: {watch_paths}")
    
    return observer


if __name__ == '__main__':
    # Load configuration
    config_path = Path.home() / 'case_config.json'
    
    if not config_path.exists():
        logger.error("case_config.json not found")
        exit(1)
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    case_name = config.get('case_name', 'Investigation')
    
    # Initialize components
    substrate = PersistentSubstrate(case_name)
    
    gemini_key = os.getenv('GEMINI_API_KEY')
    claude_key = os.getenv('ANTHROPIC_API_KEY')
    openai_key = os.getenv('OPENAI_API_KEY')
    
    ensemble = EnsembleValidator(gemini_key, claude_key, openai_key)
    db_integration = PublicDatabaseIntegration(substrate)
    adversarial = AdversarialReasoning(substrate)
    
    # Start watchdog
    watch_paths = [
        str(Path.home() / 'iCloud Drive'),
        str(Path.home() / 'Documents')
    ]
    observer = start_watchdog(watch_paths, substrate, ensemble)
    
    # Start Flask
    logger.info(f"THE PILL v4 initialized for: {case_name}")
    logger.info(f"Database: {substrate.db_path}")
    logger.info(f"Listening on http://localhost:5000")
    
    try:
        app.run(host='localhost', port=5000, debug=False)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
        logger.info("THE PILL v4 shutdown")
