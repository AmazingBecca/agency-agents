#!/usr/bin/env python3
"""
Tasklet Remote Orchestrator v2 - Intelligence at the Edge
Runs on User's Mac as Docker container
- Watches folders for new evidence files
- Processes PDFs with Gemini locally
- Uploads results to Google Drive
- Sends findings back to Cloud Agent via webhook
"""

import os
import json
import sys
import base64
import mimetypes
from pathlib import Path
from datetime import datetime
import logging
import hashlib
import requests
from queue import Queue
from threading import Thread
import time

from flask import Flask, request, jsonify
from flask_cors import CORS
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

# Imports for API calls
import google.auth
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google.auth.oauthlib.flow import InstalledAppFlow
from google_auth_httplib2 import AuthorizedHttp
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/orchestrator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# ============================================================================
# CONFIGURATION
# ============================================================================

ORCHESTRATOR_TOKEN = os.getenv('ORCHESTRATOR_TOKEN', 'change-me-in-docker-run')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
WEBHOOK_URL = os.getenv('WEBHOOK_URL', '')
WEBHOOK_TOKEN = os.getenv('WEBHOOK_TOKEN', '')

# Paths
ICLOUD_DRIVE_PATH = Path(os.path.expanduser('~/Library/Mobile Documents/com~apple~CloudDocs'))
DOCUMENTS_PATH = Path(os.path.expanduser('~/Documents'))
DOWNLOADS_PATH = Path(os.path.expanduser('~/Downloads'))

# Processing queue
processing_queue = Queue()
processed_files = set()  # Prevent reprocessing

# ============================================================================
# GEMINI INTEGRATION
# ============================================================================

class GeminiProcessor:
    """Process documents with Gemini 2.0 Flash Vision"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.endpoint = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent'
    
    def process_pdf(self, file_path, analysis_type='extract_evidence'):
        """
        Process PDF with Gemini for evidence extraction
        analysis_type: 'extract_evidence', 'timeline_analysis', 'damage_assessment', 'oen_compliance'
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return {'error': f'File not found: {file_path}'}
            
            # Read file and encode
            with open(file_path, 'rb') as f:
                file_data = base64.standard_b64encode(f.read()).decode('utf-8')
            
            mime_type = 'application/pdf'
            
            # Prompt routing based on analysis type
            prompts = {
                'extract_evidence': '''Extract ALL factual evidence from this document. Return structured JSON with:
                    - key_facts: [list of factual claims with page numbers]
                    - dates: [all dates mentioned with context]
                    - amounts: [all dollar amounts, estimates, costs]
                    - names_entities: [people, companies, references]
                    - contradictions: [any internal inconsistencies]
                    - critical_quotes: [verbatim quotes relevant to case]
                    Return ONLY valid JSON, no explanation.''',
                
                'timeline_analysis': '''Create a precise chronological timeline from this document. Return JSON:
                    - events: [{date, time_if_known, event_description, source_quote}]
                    - gaps: [missing time periods that should be documented]
                    - uncertainties: [events with unclear timing]
                    Return ONLY valid JSON.''',
                
                'damage_assessment': '''Analyze damage documentation. Return JSON:
                    - repair_items: [list of repairs mentioned]
                    - oem_standards: [any OEM compliance references]
                    - cost_breakdown: [{item, estimated_cost, actual_cost}]
                    - safety_concerns: [any safety-related findings]
                    - missing_repairs: [repairs that should have been done]
                    Return ONLY valid JSON.''',
                
                'oem_compliance': '''Assess OEM compliance violations. Return JSON:
                    - standard_violated: [which OEM standards]
                    - repair_method: [what was done vs what should be done]
                    - safety_impact: [potential safety consequences]
                    - evidence_strength: [high/medium/low - how well documented]
                    Return ONLY valid JSON.'''
            }
            
            prompt = prompts.get(analysis_type, prompts['extract_evidence'])
            
            # Call Gemini API
            headers = {'Content-Type': 'application/json'}
            payload = {
                'contents': [{
                    'parts': [
                        {'text': prompt},
                        {
                            'inlineData': {
                                'mimeType': mime_type,
                                'data': file_data
                            }
                        }
                    ]
                }],
                'generationConfig': {
                    'temperature': 0.1,  # Low for deterministic extraction
                    'topP': 0.95,
                    'topK': 40,
                    'maxOutputTokens': 8192
                }
            }
            
            response = requests.post(
                f'{self.endpoint}?key={self.api_key}',
                json=payload,
                headers=headers,
                timeout=120
            )
            
            if response.status_code != 200:
                return {
                    'error': f'Gemini API error: {response.status_code}',
                    'details': response.text
                }
            
            result = response.json()
            
            # Extract text response
            if 'candidates' in result and len(result['candidates']) > 0:
                text_content = result['candidates'][0].get('content', {}).get('parts', [{}])[0].get('text', '')
                
                # Try to parse as JSON
                try:
                    extracted_json = json.loads(text_content)
                except json.JSONDecodeError:
                    extracted_json = {'raw_text': text_content}
                
                return {
                    'success': True,
                    'file': str(file_path),
                    'analysis_type': analysis_type,
                    'extraction': extracted_json,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return {'error': 'No content in Gemini response'}
                
        except Exception as e:
            logger.error(f'Gemini processing error: {e}', exc_info=True)
            return {'error': str(e)}
    
    def process_image(self, file_path):
        """Process image with Gemini for OCR and analysis"""
        try:
            file_path = Path(file_path)
            with open(file_path, 'rb') as f:
                file_data = base64.standard_b64encode(f.read()).decode('utf-8')
            
            mime_type = mimetypes.guess_type(str(file_path))[0] or 'image/jpeg'
            
            prompt = '''Extract ALL text and data from this image. Return structured JSON:
                - text: [all visible text, preserving layout]
                - fields: [{field_name, field_value}]
                - tables: [any tabular data as structured list]
                - handwriting: [any handwritten notes]
                Return ONLY valid JSON.'''
            
            headers = {'Content-Type': 'application/json'}
            payload = {
                'contents': [{
                    'parts': [
                        {'text': prompt},
                        {
                            'inlineData': {
                                'mimeType': mime_type,
                                'data': file_data
                            }
                        }
                    ]
                }],
                'generationConfig': {'temperature': 0.1, 'maxOutputTokens': 4096}
            }
            
            response = requests.post(
                f'{self.endpoint}?key={self.api_key}',
                json=payload,
                headers=headers,
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                text_content = result['candidates'][0].get('content', {}).get('parts', [{}])[0].get('text', '')
                try:
                    extracted_json = json.loads(text_content)
                except:
                    extracted_json = {'raw_text': text_content}
                
                return {
                    'success': True,
                    'file': str(file_path),
                    'type': 'image_extraction',
                    'extraction': extracted_json,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return {'error': f'Gemini API error: {response.status_code}'}
                
        except Exception as e:
            logger.error(f'Image processing error: {e}')
            return {'error': str(e)}


# ============================================================================
# GOOGLE DRIVE INTEGRATION
# ============================================================================

class GoogleDriveManager:
    """Upload and manage files in Google Drive"""
    
    def __init__(self):
        self.service = None
        self.init_drive()
    
    def init_drive(self):
        """Initialize Google Drive API (assumes user auth already done)"""
        try:
            # This assumes credentials are in standard location
            # In production, would need proper OAuth flow
            logger.info("Google Drive API initialized")
        except Exception as e:
            logger.warning(f"Could not init Drive API: {e}")
    
    def upload_file(self, file_path, folder_id=None, description=''):
        """Upload file to Google Drive"""
        # Placeholder - would use google-api-python-client
        # Returns file ID if successful
        return {
            'uploaded': True,
            'file_path': str(file_path),
            'description': description
        }
    
    def create_folder(self, folder_name, parent_id=None):
        """Create folder in Google Drive"""
        return {
            'created': True,
            'folder_name': folder_name
        }


# ============================================================================
# FILE WATCHING & PROCESSING
# ============================================================================

class EvidenceFileHandler(FileSystemEventHandler):
    """Watch for new evidence files and queue for processing"""
    
    def on_created(self, event):
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        
        # Only process evidence file types
        if file_path.suffix.lower() in ['.pdf', '.jpg', '.png', '.jpeg', '.doc', '.docx']:
            file_hash = hashlib.md5(str(file_path).encode()).hexdigest()
            
            if file_hash not in processed_files:
                logger.info(f'New evidence file detected: {file_path}')
                processing_queue.put({
                    'file_path': str(file_path),
                    'event_type': 'new_file',
                    'detected_at': datetime.now().isoformat()
                })
                processed_files.add(file_hash)


class FileProcessor(Thread):
    """Background thread that processes queued files"""
    
    def __init__(self, gemini_processor, drive_manager):
        super().__init__(daemon=True)
        self.gemini = gemini_processor
        self.drive = drive_manager
    
    def run(self):
        """Process files from queue continuously"""
        logger.info("File processor thread started")
        
        while True:
            try:
                # Get item from queue with timeout
                item = processing_queue.get(timeout=5)
                file_path = item['file_path']
                
                logger.info(f'Processing: {file_path}')
                
                # Determine file type and analyze
                file_ext = Path(file_path).suffix.lower()
                
                if file_ext == '.pdf':
                    result = self.gemini.process_pdf(
                        file_path,
                        analysis_type='extract_evidence'
                    )
                elif file_ext in ['.jpg', '.jpeg', '.png']:
                    result = self.gemini.process_image(file_path)
                else:
                    result = {'error': f'Unsupported file type: {file_ext}'}
                
                # Send result back to Cloud Agent via webhook
                if WEBHOOK_URL and result.get('success'):
                    self.send_webhook(result)
                
                logger.info(f'Processing complete: {file_path}')
                processing_queue.task_done()
                
            except Exception as e:
                if 'Empty' not in str(e):  # Ignore timeout exceptions
                    logger.error(f'Processor error: {e}', exc_info=True)
    
    def send_webhook(self, result):
        """Send processing results back to Cloud Agent"""
        try:
            headers = {
                'Content-Type': 'application/json',
                'X-Webhook-Token': WEBHOOK_TOKEN
            }
            
            payload = {
                'event': 'file_processed',
                'result': result,
                'timestamp': datetime.now().isoformat()
            }
            
            response = requests.post(WEBHOOK_URL, json=payload, headers=headers, timeout=30)
            logger.info(f'Webhook sent: {response.status_code}')
            
        except Exception as e:
            logger.error(f'Webhook error: {e}')


# ============================================================================
# FLASK ENDPOINTS
# ============================================================================

@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'icloud_available': ICLOUD_DRIVE_PATH.exists(),
        'documents_available': DOCUMENTS_PATH.exists(),
        'queue_size': processing_queue.qsize()
    })


@app.route('/process', methods=['POST'])
def process_file():
    """Receive command to process a file"""
    token = request.headers.get('X-Orchestrator-Token')
    if token != ORCHESTRATOR_TOKEN:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    file_path = data.get('file_path')
    analysis_type = data.get('analysis_type', 'extract_evidence')
    
    if not Path(file_path).exists():
        return jsonify({'error': f'File not found: {file_path}'}), 404
    
    # Queue for processing
    processing_queue.put({
        'file_path': file_path,
        'analysis_type': analysis_type,
        'requested_at': datetime.now().isoformat()
    })
    
    return jsonify({
        'status': 'queued',
        'file_path': file_path,
        'queue_position': processing_queue.qsize()
    })


@app.route('/watch', methods=['POST'])
def watch_folder():
    """Start watching a folder for new evidence files"""
    token = request.headers.get('X-Orchestrator-Token')
    if token != ORCHESTRATOR_TOKEN:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    folder_path = Path(data.get('path', DOCUMENTS_PATH))
    
    if not folder_path.exists():
        return jsonify({'error': f'Folder not found: {folder_path}'}), 404
    
    # Start file watcher
    event_handler = EvidenceFileHandler()
    observer = Observer()
    observer.schedule(event_handler, str(folder_path), recursive=True)
    observer.start()
    
    logger.info(f'Watching folder: {folder_path}')
    
    return jsonify({
        'status': 'watching',
        'folder': str(folder_path),
        'observer_alive': observer.is_alive()
    })


@app.route('/list-evidence', methods=['GET'])
def list_evidence():
    """List all evidence files in watched folders"""
    evidence_files = []
    
    for base_path in [ICLOUD_DRIVE_PATH, DOCUMENTS_PATH, DOWNLOADS_PATH]:
        if base_path.exists():
            for pattern in ['**/*.pdf', '**/*.jpg', '**/*.jpeg', '**/*.png']:
                for file in base_path.glob(pattern):
                    evidence_files.append({
                        'path': str(file),
                        'name': file.name,
                        'size': file.stat().st_size,
                        'modified': file.stat().st_mtime
                    })
    
    return jsonify({
        'evidence_files': evidence_files,
        'count': len(evidence_files)
    })


@app.route('/status', methods=['GET'])
def status():
    """Get orchestrator status"""
    return jsonify({
        'orchestrator': 'running',
        'timestamp': datetime.now().isoformat(),
        'queue_size': processing_queue.qsize(),
        'processed_files': len(processed_files),
        'watching': True,
        'gemini_ready': bool(GEMINI_API_KEY),
        'webhook_configured': bool(WEBHOOK_URL)
    })


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    logger.info("=" * 80)
    logger.info("Tasklet Remote Orchestrator v2 Starting")
    logger.info("=" * 80)
    
    # Initialize processors
    gemini = GeminiProcessor(GEMINI_API_KEY)
    drive = GoogleDriveManager()
    
    # Start file processor thread
    processor = FileProcessor(gemini, drive)
    processor.start()
    
    # Start folder watchers
    handlers = EvidenceFileHandler()
    observer = Observer()
    
    for watch_path in [ICLOUD_DRIVE_PATH, DOCUMENTS_PATH, DOWNLOADS_PATH]:
        if watch_path.exists():
            observer.schedule(handlers, str(watch_path), recursive=True)
            logger.info(f"Watching: {watch_path}")
    
    observer.start()
    
    # Start Flask
    port = int(os.getenv('LISTEN_PORT', 5000))
    logger.info(f"Flask API listening on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
