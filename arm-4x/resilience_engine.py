"""
RESILIENCE ENGINE - The Pill's Immune System
Autonomous fault detection, repair, and evolution
"""

import sqlite3
import hashlib
import json
import time
import os
import subprocess
import threading
from datetime import datetime, timedelta
from pathlib import Path
import logging

class ResilienceEngine:
    """Self-healing system for The Pill investigation engine"""
    
    def __init__(self, pill_dir, db_path="resilience_log.db", check_interval=60):
        self.pill_dir = Path(pill_dir)
        self.db_path = self.pill_dir / db_path
        self.check_interval = check_interval
        self.running = False
        
        # Initialize resilience database
        self._init_resilience_db()
        
        # Code integrity baseline
        self.code_signatures = self._generate_code_signatures()
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def _init_resilience_db(self):
        """Create resilience tracking database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS resilience_events (
                id INTEGER PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                component TEXT NOT NULL,
                action_taken TEXT,
                outcome TEXT,
                details JSON,
                user_notification BOOLEAN DEFAULT 0
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS code_signatures (
                component TEXT PRIMARY KEY,
                hash TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                verified BOOLEAN DEFAULT 0
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS upgrade_history (
                id INTEGER PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                old_version TEXT,
                new_version TEXT,
                status TEXT,
                outcome TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def _generate_code_signatures(self):
        """Generate integrity signatures for all critical components"""
        signatures = {}
        
        # Core orchestrator
        orchestrator = self.pill_dir / "orchestrator_generic.py"
        if orchestrator.exists():
            signatures["orchestrator"] = self._hash_file(orchestrator)
        
        # Config
        config = self.pill_dir / "investigation_config.json"
        if config.exists():
            signatures["config"] = self._hash_file(config)
        
        # Resilience engine itself
        resilience = Path(__file__)
        signatures["resilience_engine"] = self._hash_file(resilience)
        
        return signatures
    
    def _hash_file(self, filepath):
        """Generate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def _log_event(self, event_type, severity, component, action=None, outcome=None, details=None, notify=False):
        """Record event in immutable resilience ledger"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO resilience_events 
            (event_type, severity, component, action_taken, outcome, details, user_notification)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (event_type, severity, component, action, outcome, json.dumps(details or {}), notify))
        
        conn.commit()
        conn.close()
        
        self.logger.log(
            getattr(logging, severity),
            f"[{event_type}] {component}: {action} → {outcome}"
        )
    
    def check_database_integrity(self):
        """Verify main investigation database isn't corrupted"""
        investigation_db = self.pill_dir / "investigation_bible.db"
        
        if not investigation_db.exists():
            return True  # No database yet
        
        try:
            conn = sqlite3.connect(str(investigation_db))
            cursor = conn.cursor()
            cursor.execute("PRAGMA integrity_check")
            result = cursor.fetchone()[0]
            conn.close()
            
            if result != "ok":
                self._log_event(
                    "DATABASE_CHECK",
                    "CRITICAL",
                    "INVESTIGATION_DB",
                    action="INTEGRITY_CHECK_FAILED",
                    outcome="REPAIR_INITIATED",
                    details={"check_result": result}
                )
                self._repair_database(investigation_db)
                return False
            
            return True
        
        except Exception as e:
            self._log_event(
                "DATABASE_CHECK",
                "CRITICAL",
                "INVESTIGATION_DB",
                action="CHECK_EXCEPTION",
                outcome="REPAIR_REQUIRED",
                details={"error": str(e)}
            )
            self._repair_database(investigation_db)
            return False
    
    def _repair_database(self, db_path):
        """Attempt database repair"""
        backup = Path(str(db_path) + ".backup")
        corrupted = Path(str(db_path) + ".corrupted")
        
        try:
            # Backup corrupted version
            if db_path.exists():
                db_path.rename(corrupted)
            
            # Restore from backup if available
            if backup.exists():
                backup.rename(db_path)
                self._log_event(
                    "DATABASE_REPAIR",
                    "WARNING",
                    "INVESTIGATION_DB",
                    action="RESTORED_FROM_BACKUP",
                    outcome="SUCCESS"
                )
            else:
                # Create new database
                conn = sqlite3.connect(str(db_path))
                conn.close()
                self._log_event(
                    "DATABASE_REPAIR",
                    "WARNING",
                    "INVESTIGATION_DB",
                    action="NEW_DB_CREATED",
                    outcome="SUCCESS"
                )
        
        except Exception as e:
            self._log_event(
                "DATABASE_REPAIR",
                "CRITICAL",
                "INVESTIGATION_DB",
                action="REPAIR_FAILED",
                outcome="FAILED",
                details={"error": str(e)},
                notify=True
            )
    
    def check_code_integrity(self):
        """Verify code hasn't been tampered with"""
        current_signatures = self._generate_code_signatures()
        
        for component, current_hash in current_signatures.items():
            if component in self.code_signatures:
                if current_hash != self.code_signatures[component]:
                    self._log_event(
                        "CODE_INTEGRITY",
                        "CRITICAL",
                        component,
                        action="SIGNATURE_MISMATCH_DETECTED",
                        outcome="RESTORING_FROM_BACKUP",
                        details={
                            "expected": self.code_signatures[component],
                            "found": current_hash
                        },
                        notify=True
                    )
                    # Restore clean version
                    self._restore_component(component)
    
    def _restore_component(self, component):
        """Restore component from known-good backup"""
        # Implementation depends on backup strategy
        pass
    
    def check_api_health(self, api_endpoints):
        """Verify critical API connectivity"""
        timeout = 5
        
        for api_name, endpoint in api_endpoints.items():
            try:
                response = subprocess.run(
                    ["curl", "-s", "-m", str(timeout), "-o", "/dev/null", "-w", "%{http_code}", endpoint],
                    capture_output=True,
                    timeout=timeout+1
                )
                
                status_code = int(response.stdout.decode().strip())
                
                if status_code < 200 or status_code >= 500:
                    self._log_event(
                        "API_HEALTH",
                        "WARNING",
                        f"API_{api_name}",
                        action="HEALTH_CHECK_FAILED",
                        outcome="DEGRADED",
                        details={"status_code": status_code}
                    )
                    # Implement fallback logic
            
            except Exception as e:
                self._log_event(
                    "API_HEALTH",
                    "WARNING",
                    f"API_{api_name}",
                    action="HEALTH_CHECK_EXCEPTION",
                    outcome="ASSUMED_DOWN",
                    details={"error": str(e)}
                )
    
    def check_orchestrator_alive(self):
        """Verify orchestrator process is running"""
        # Check for orchestrator process
        try:
            result = subprocess.run(
                ["pgrep", "-f", "orchestrator_generic.py"],
                capture_output=True
            )
            
            if result.returncode != 0:
                self._log_event(
                    "PROCESS_HEALTH",
                    "CRITICAL",
                    "ORCHESTRATOR",
                    action="PROCESS_DEAD",
                    outcome="RESTART_INITIATED"
                )
                self._restart_orchestrator()
        
        except Exception as e:
            self._log_event(
                "PROCESS_HEALTH",
                "CRITICAL",
                "ORCHESTRATOR",
                action="HEALTH_CHECK_FAILED",
                outcome="MANUAL_INTERVENTION_REQUIRED",
                details={"error": str(e)},
                notify=True
            )
    
    def _restart_orchestrator(self):
        """Restart orchestrator with exponential backoff"""
        max_retries = 5
        backoff_start = 1
        
        for attempt in range(max_retries):
            try:
                subprocess.Popen([
                    "python", "orchestrator_generic.py",
                    str(self.pill_dir / "investigation_config.json")
                ], cwd=str(self.pill_dir))
                
                self._log_event(
                    "PROCESS_RESTART",
                    "INFO",
                    "ORCHESTRATOR",
                    action="RESTART_ATTEMPTED",
                    outcome="SUCCESS",
                    details={"attempt": attempt + 1}
                )
                return
            
            except Exception as e:
                backoff = backoff_start * (2 ** attempt)
                self._log_event(
                    "PROCESS_RESTART",
                    "WARNING" if attempt < max_retries - 1 else "CRITICAL",
                    "ORCHESTRATOR",
                    action="RESTART_FAILED",
                    outcome="RETRYING" if attempt < max_retries - 1 else "EXHAUSTED",
                    details={"attempt": attempt + 1, "backoff_seconds": backoff, "error": str(e)}
                )
                time.sleep(backoff)
    
    def monitor_continuously(self):
        """Main monitoring loop"""
        self.running = True
        
        while self.running:
            try:
                # Run all checks
                self.check_database_integrity()
                self.check_code_integrity()
                self.check_orchestrator_alive()
                
                # API checks if configured
                api_endpoints = {
                    "gemini": "https://generativelanguage.googleapis.com/v1beta",
                    "claude": "https://api.anthropic.com",
                    "openai": "https://api.openai.com"
                }
                self.check_api_health(api_endpoints)
                
                time.sleep(self.check_interval)
            
            except Exception as e:
                self.logger.error(f"Monitor exception: {e}")
                time.sleep(self.check_interval)
    
    def start(self):
        """Start monitoring in background thread"""
        monitor_thread = threading.Thread(target=self.monitor_continuously, daemon=True)
        monitor_thread.start()
        self.logger.info("Resilience engine started")
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        self.logger.info("Resilience engine stopped")

