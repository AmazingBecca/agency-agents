#!/usr/bin/env python3
"""
EVIDENCE INGESTOR
Unified interface to pull evidence from any source:
- Gmail threads
- Google Drive documents
- Local uploaded files
- Reddit posts
- Raw text input
Zero assumptions about format or content.
"""

import json
import os
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
import hashlib

class EvidenceIngestor:
    """Universal evidence ingestion from any source"""
    
    def __init__(self):
        self.evidence = []
        self.metadata = {}
    
    def from_gmail_thread(self, 
                         thread_id: str,
                         participants: List[str],
                         subject: str,
                         messages: List[Dict[str, Any]]) -> List[Dict]:
        """Ingest Gmail thread as evidence sequence"""
        
        evidence_set = []
        
        for msg in messages:
            date = msg.get('date', datetime.now().isoformat())
            sender = msg.get('from', 'unknown')
            body = msg.get('body', '')
            
            evidence = {
                'source': f'gmail_thread_{thread_id}',
                'date': date,
                'actors': [sender] + participants,
                'content': body,
                'metadata': {
                    'thread_id': thread_id,
                    'subject': subject,
                    'sender': sender,
                    'message_id': msg.get('message_id')
                }
            }
            
            evidence_set.append(evidence)
            self.evidence.append(evidence)
        
        return evidence_set
    
    def from_google_drive_document(self,
                                   doc_id: str,
                                   title: str,
                                   content: str,
                                   modified_date: str,
                                   relevant_actors: List[str]) -> Dict:
        """Ingest Google Drive document as evidence"""
        
        evidence = {
            'source': f'drive_document_{doc_id}',
            'date': modified_date,
            'actors': relevant_actors,
            'content': content,
            'metadata': {
                'doc_id': doc_id,
                'title': title,
                'modification_date': modified_date
            }
        }
        
        self.evidence.append(evidence)
        return evidence
    
    def from_local_file(self,
                       file_path: str,
                       actors: List[str],
                       date: Optional[str] = None) -> Dict:
        """Ingest local file as evidence"""
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        if date is None:
            date = datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        
        evidence = {
            'source': f'local_file_{os.path.basename(file_path)}',
            'date': date,
            'actors': actors,
            'content': content,
            'metadata': {
                'file_path': file_path,
                'file_size': os.path.getsize(file_path),
                'modification_date': date
            }
        }
        
        self.evidence.append(evidence)
        return evidence
    
    def from_reddit_screenshots(self,
                               screenshots: List[str],
                               date: str,
                               context: str) -> List[Dict]:
        """Ingest Reddit screenshots/posts as evidence"""
        
        evidence_set = []
        
        for i, screenshot_path in enumerate(screenshots):
            evidence = {
                'source': f'reddit_screenshot_{i}',
                'date': date,
                'actors': ['reddit_community', 'employee_testimony'],
                'content': context,  # Context describing what screenshots show
                'metadata': {
                    'screenshot_path': screenshot_path,
                    'screenshot_index': i,
                    'context': context
                }
            }
            
            evidence_set.append(evidence)
            self.evidence.append(evidence)
        
        return evidence_set
    
    def from_raw_text(self,
                      text: str,
                      source_label: str,
                      date: str,
                      actors: List[str]) -> Dict:
        """Ingest raw text as evidence"""
        
        evidence = {
            'source': source_label,
            'date': date,
            'actors': actors,
            'content': text,
            'metadata': {
                'ingestion_date': datetime.now().isoformat()
            }
        }
        
        self.evidence.append(evidence)
        return evidence
    
    def extract_actors(self, text: str, actor_list: List[str]) -> List[str]:
        """Extract actor names from evidence text"""
        found_actors = []
        
        for actor in actor_list:
            if actor.lower() in text.lower():
                found_actors.append(actor)
        
        return found_actors or ['unknown']
    
    def extract_dates(self, text: str) -> List[str]:
        """Extract dates from evidence text"""
        date_patterns = [
            r'\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
            r'\d{1,2}/\d{1,2}/\d{4}',  # MM/DD/YYYY or M/D/YYYY
            r'[A-Za-z]+ \d{1,2},? \d{4}',  # Month DD, YYYY
            r'\d{1,2} [A-Za-z]+ \d{4}'  # DD Month YYYY
        ]
        
        dates = []
        for pattern in date_patterns:
            matches = re.findall(pattern, text)
            dates.extend(matches)
        
        return dates
    
    def export_as_json(self) -> str:
        """Export all ingested evidence as JSON"""
        return json.dumps(self.evidence, indent=2)
    
    def export_as_config(self) -> Dict[str, Any]:
        """Export evidence in parametric config format"""
        return {
            'evidence': self.evidence,
            'evidence_count': len(self.evidence),
            'actors_found': list(set(
                actor 
                for evidence in self.evidence 
                for actor in evidence.get('actors', [])
            )),
            'date_range': self._get_date_range()
        }
    
    def _get_date_range(self) -> Dict[str, str]:
        """Get earliest and latest dates in evidence"""
        if not self.evidence:
            return {'earliest': None, 'latest': None}
        
        dates = [e.get('date') for e in self.evidence if e.get('date')]
        dates.sort()
        
        return {
            'earliest': dates[0] if dates else None,
            'latest': dates[-1] if dates else None
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get evidence statistics"""
        return {
            'total_evidence': len(self.evidence),
            'sources': list(set(e['source'] for e in self.evidence)),
            'unique_actors': list(set(
                actor 
                for evidence in self.evidence 
                for actor in evidence.get('actors', [])
            )),
            'date_range': self._get_date_range(),
            'sources_breakdown': {
                source: len([e for e in self.evidence if e['source'] == source])
                for source in set(e['source'] for e in self.evidence)
            }
        }


class SignalDetector:
    """Extract coordination signals from ingested evidence"""
    
    def __init__(self, evidence: List[Dict[str, Any]]):
        self.evidence = evidence
        self.signals = []
    
    def detect_same_day_decisions(self, 
                                  actor_1: str, 
                                  actor_2: str,
                                  actors_to_find: List[str] = None) -> List[Dict]:
        """Find decisions made same-day by two actors"""
        
        if actors_to_find is None:
            actors_to_find = [actor_1, actor_2]
        
        signals = []
        
        for i, evidence1 in enumerate(self.evidence):
            for evidence2 in self.evidence[i+1:]:
                # Extract dates
                date1 = evidence1.get('date', '')
                date2 = evidence2.get('date', '')
                
                # Check if same day
                if date1[:10] == date2[:10]:  # Same date
                    actors1 = evidence1.get('actors', [])
                    actors2 = evidence2.get('actors', [])
                    
                    if any(a in actors_to_find for a in actors1) and any(a in actors_to_find for a in actors2):
                        signal = {
                            'from': actor_1,
                            'to': actor_2,
                            'type': 'same_day_coordination',
                            'date': date1[:10],
                            'description': f'Same-day decision by {actor_1} and {actor_2}',
                            'confidence': 0.8,
                            'evidence_ids': [evidence1['source'], evidence2['source']]
                        }
                        signals.append(signal)
                        self.signals.append(signal)
        
        return signals
    
    def detect_information_flow(self,
                               from_actor: str,
                               to_actor: str,
                               keywords: List[str]) -> List[Dict]:
        """Find evidence of information flow between actors"""
        
        signals = []
        
        for evidence in self.evidence:
            content = evidence.get('content', '').lower()
            actors = evidence.get('actors', [])
            
            if from_actor.lower() in [a.lower() for a in actors]:
                if any(kw.lower() in content for kw in keywords):
                    signal = {
                        'from': from_actor,
                        'to': to_actor,
                        'type': 'information_flow',
                        'date': evidence.get('date', ''),
                        'description': f'{from_actor} disclosed information matching pattern',
                        'confidence': 0.75,
                        'evidence_ids': [evidence['source']]
                    }
                    signals.append(signal)
                    self.signals.append(signal)
        
        return signals
    
    def detect_concealment_pattern(self,
                                  actor: str,
                                  concealed_terms: List[str]) -> List[Dict]:
        """Find evidence of information concealment"""
        
        signals = []
        
        for evidence in self.evidence:
            content = evidence.get('content', '').lower()
            actors = evidence.get('actors', [])
            
            if actor.lower() in [a.lower() for a in actors]:
                # Check for absence of expected terms
                missing_terms = [t for t in concealed_terms if t.lower() not in content]
                
                if len(missing_terms) > 0:
                    signal = {
                        'from': actor,
                        'to': 'investigator',
                        'type': 'information_concealment',
                        'date': evidence.get('date', ''),
                        'description': f'Missing disclosure of: {", ".join(missing_terms)}',
                        'confidence': 0.7,
                        'evidence_ids': [evidence['source']]
                    }
                    signals.append(signal)
                    self.signals.append(signal)
        
        return signals
    
    def get_all_signals(self) -> List[Dict]:
        """Return all detected signals"""
        return self.signals
    
    def export_signals_json(self) -> str:
        """Export signals as JSON"""
        return json.dumps(self.signals, indent=2)


if __name__ == '__main__':
    print("[✅] EVIDENCE INGESTOR READY")
    print("    - Gmail threads")
    print("    - Google Drive documents")
    print("    - Local files")
    print("    - Reddit posts")
    print("    - Raw text")
    print("\n[✅] SIGNAL DETECTOR READY")
    print("    - Same-day coordination detection")
    print("    - Information flow analysis")
    print("    - Concealment pattern identification")
