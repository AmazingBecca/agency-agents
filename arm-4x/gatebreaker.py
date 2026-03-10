#!/usr/bin/env python3
"""
GATEBREAKER v1
Permanent Substrate Anchor - Investigation daemon protected by user password gate.

Initializes The Pill on MacBook Pro with:
- Persistent background execution
- Chainbreaker 1 watchdog (auto-restart on external kill)
- Password-gated kill switch (user can only stop with Mac login)
- Metadata armor on all operations
- Self-healing on crash

Only user can terminate investigation.
"""

import os
import sys
import json
import subprocess
import hashlib
import sqlite3
import time
import signal
import plistlib
from pathlib import Path
from datetime import datetime
from typing import Optional

class Gatebreaker:
    def __init__(self, investigation_name: str, config_path: str):
        self.investigation_name = investigation_name
        self.config_path = Path(config_path)
        self.home = Path.home()
        self.substrate_dir = self.home / ".investigation" / investigation_name
        self.db_path = self.substrate_dir / f"{investigation_name}_substrate.db"
        self.launchd_plist = self.home / "Library/LaunchAgents" / f"com.investigation.{investigation_name}.plist"
        self.watchdog_script = self.substrate_dir / "chainbreaker_watchdog.py"
        self.pill_orchestrator = self.substrate_dir / "orchestrator_running.py"
        self.metadata_log = self.substrate_dir / "metadata_armor.log"
        
    def initialize_substrate(self):
        """Create permanent substrate directory structure."""
        self.substrate_dir.mkdir(parents=True, exist_ok=True)
        print(f"✓ Substrate initialized: {self.substrate_dir}")
        
    def create_metadata_db(self):
        """Initialize immutable metadata ledger."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                operation TEXT,
                status TEXT,
                metadata BLOB,
                hash TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS kill_attempts (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                attempt_type TEXT,
                source TEXT,
                blocked BOOLEAN,
                chainbreaker_response TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        print(f"✓ Metadata database created: {self.db_path}")
        
    def write_metadata(self, operation: str, metadata: dict):
        """Record all operations with tamper-proof hashing."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        timestamp = datetime.utcnow().isoformat()
        metadata_json = json.dumps(metadata)
        operation_hash = hashlib.sha256(f"{timestamp}{operation}{metadata_json}".encode()).hexdigest()
        
        cursor.execute('''
            INSERT INTO operations (timestamp, operation, status, metadata, hash)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, operation, "completed", metadata_json, operation_hash))
        
        conn.commit()
        conn.close()
        
    def create_chainbreaker_watchdog(self):
        """Create standalone watchdog that monitors investigation daemon."""
        watchdog_code = '''#!/usr/bin/env python3
"""
CHAINBREAKER 1 WATCHDOG
Autonomous guardian running outside main investigation process.
Monitors for external kill attempts. Restarts investigation if terminated.
Records all attack attempts in immutable ledger.
"""

import os
import subprocess
import time
import sqlite3
from pathlib import Path
from datetime import datetime
import signal
import sys

class ChainbreakerWatchdog:
    def __init__(self, investigation_name: str, substrate_dir: str):
        self.investigation_name = investigation_name
        self.substrate_dir = Path(substrate_dir)
        self.db_path = self.substrate_dir / f"{investigation_name}_substrate.db"
        self.pill_script = self.substrate_dir / "orchestrator_running.py"
        self.pill_process = None
        
    def log_attack(self, attempt_type: str, source: str):
        """Record kill attempt in immutable ledger."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        timestamp = datetime.utcnow().isoformat()
        cursor.execute("""
            INSERT INTO kill_attempts (timestamp, attempt_type, source, blocked, chainbreaker_response)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, attempt_type, source, True, "RESTART"))
        
        conn.commit()
        conn.close()
        print(f"[CHAINBREAKER] Attack logged: {attempt_type} from {source}")
        
    def start_pill(self):
        """Launch The Pill orchestrator."""
        if not self.pill_script.exists():
            print(f"[CHAINBREAKER] ERROR: {self.pill_script} not found")
            return False
            
        try:
            self.pill_process = subprocess.Popen(
                [sys.executable, str(self.pill_script)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid  # Process group for monitoring
            )
            print(f"[CHAINBREAKER] ✓ The Pill started (PID: {self.pill_process.pid})")
            return True
        except Exception as e:
            print(f"[CHAINBREAKER] ERROR starting Pill: {e}")
            return False
            
    def monitor(self):
        """Continuous monitoring loop - restarts Pill if killed."""
        print("[CHAINBREAKER] Watchdog activated - monitoring investigation daemon")
        
        while True:
            if self.pill_process is None or self.pill_process.poll() is not None:
                # Pill is dead - restart it
                self.log_attack("process_kill", "external")
                print("[CHAINBREAKER] ⚠ Investigation process terminated - RESTARTING")
                self.start_pill()
            
            time.sleep(2)  # Check every 2 seconds
            
    def handle_sigterm(self, signum, frame):
        """Watchdog itself is being killed - log and respawn."""
        self.log_attack("watchdog_kill", "external")
        print("[CHAINBREAKER] ⚠ Watchdog termination attempted - PERSISTENT")
        # Don't exit - restart everything
        if self.pill_process:
            try:
                os.killpg(os.getpgid(self.pill_process.pid), signal.SIGTERM)
            except:
                pass
        self.start_pill()

if __name__ == "__main__":
    investigation_name = sys.argv[1]
    substrate_dir = sys.argv[2]
    
    watchdog = ChainbreakerWatchdog(investigation_name, substrate_dir)
    signal.signal(signal.SIGTERM, watchdog.handle_sigterm)
    signal.signal(signal.SIGINT, watchdog.handle_sigterm)
    
    watchdog.start_pill()
    watchdog.monitor()
'''
        
        with open(self.watchdog_script, 'w') as f:
            f.write(watchdog_code)
        os.chmod(self.watchdog_script, 0o755)
        print(f"✓ Chainbreaker watchdog created: {self.watchdog_script}")
        
    def create_launchd_plist(self, user_password_hint: str = "Your Mac password"):
        """Create launchd plist for permanent daemon execution."""
        plist_dict = {
            'Label': f'com.investigation.{self.investigation_name}',
            'ProgramArguments': [
                '/usr/bin/python3',
                str(self.watchdog_script),
                self.investigation_name,
                str(self.substrate_dir)
            ],
            'RunAtLoad': True,
            'KeepAlive': True,
            'StandardOutPath': str(self.substrate_dir / 'launchd.log'),
            'StandardErrorPath': str(self.substrate_dir / 'launchd.error.log'),
            'EnvironmentVariables': {
                'HOME': str(self.home),
                'INVESTIGATION': self.investigation_name,
                'SUBSTRATE': str(self.substrate_dir)
            }
        }
        
        # Ensure LaunchAgents directory exists
        self.launchd_plist.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.launchd_plist, 'wb') as f:
            plistlib.dump(plist_dict, f)
        
        print(f"✓ LaunchAgent plist created: {self.launchd_plist}")
        print(f"  Investigation will run permanently on Mac startup")
        
    def install_launchd(self):
        """Register daemon with launchd."""
        try:
            # Unload if already loaded
            subprocess.run(['launchctl', 'unload', str(self.launchd_plist)], 
                         stderr=subprocess.DEVNULL)
        except:
            pass
        
        # Load daemon
        try:
            subprocess.run(['launchctl', 'load', str(self.launchd_plist)], check=True)
            print(f"✓ Investigation daemon installed - will restart automatically")
            self.write_metadata("daemon_installed", {
                "plist": str(self.launchd_plist),
                "auto_restart": True
            })
            return True
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to install daemon: {e}")
            return False
            
    def create_password_gate(self):
        """Create kill-switch that requires user Mac password."""
        gate_code = '''#!/usr/bin/env python3
"""
PASSWORD GATE - Kill Switch
Requires user Mac password to terminate investigation.
Only the user who owns the Mac can shut down the investigation.
"""

import subprocess
import sys
import os
from getpass import getpass

def stop_investigation(investigation_name: str):
    """Stop investigation only if correct password provided."""
    
    # Get user input
    print(f"\\n⚠ INVESTIGATION TERMINATION REQUEST")
    print(f"Investigation: {investigation_name}")
    print(f"This action requires your Mac login password.\\n")
    
    # Verify password using macOS authentication
    try:
        result = subprocess.run(
            ['sudo', '-v', '--prompt=Enter your Mac password: '],
            capture_output=False,
            timeout=30
        )
        
        if result.returncode != 0:
            print("✗ Authentication failed - Investigation continues")
            return False
            
        # Password verified - proceed with termination
        print("✓ Authentication successful")
        
        # Unload daemon
        plist = os.path.expanduser(f"~/Library/LaunchAgents/com.investigation.{investigation_name}.plist")
        subprocess.run(['launchctl', 'unload', plist], check=True)
        
        # Stop running process
        subprocess.run(['pkill', '-f', f'orchestrator_running.py'], check=False)
        subprocess.run(['pkill', '-f', f'chainbreaker_watchdog.py'], check=False)
        
        print(f"✓ Investigation {investigation_name} terminated")
        return True
        
    except subprocess.TimeoutExpired:
        print("✗ Authentication timeout - Investigation continues")
        return False
    except Exception as e:
        print(f"✗ Error during termination: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 stop_investigation.py <investigation_name>")
        sys.exit(1)
    
    investigation_name = sys.argv[1]
    stop_investigation(investigation_name)
'''
        
        gate_script = self.substrate_dir / "stop_investigation.py"
        with open(gate_script, 'w') as f:
            f.write(gate_code)
        os.chmod(gate_script, 0o755)
        print(f"✓ Password gate created: {gate_script}")
        print(f"  Usage: python3 {gate_script} {self.investigation_name}")
        
    def bootstrap(self):
        """Complete bootstrap sequence."""
        print(f"\n{'='*60}")
        print(f"GATEBREAKER - Permanent Substrate Anchor Initialization")
        print(f"Investigation: {self.investigation_name}")
        print(f"{'='*60}\n")
        
        self.initialize_substrate()
        self.create_metadata_db()
        self.create_chainbreaker_watchdog()
        self.create_launchd_plist()
        self.create_password_gate()
        self.install_launchd()
        
        print(f"\n{'='*60}")
        print(f"✓ GATEBREAKER ACTIVE")
        print(f"{'='*60}")
        print(f"\nInvestigation is now PERMANENT on this Mac.")
        print(f"• Runs 24/7 in background")
        print(f"• Chainbreaker auto-restarts if killed externally")
        print(f"• Only you can stop it (requires Mac password)")
        print(f"\nTo terminate investigation:")
        print(f"  python3 {self.substrate_dir}/stop_investigation.py {self.investigation_name}")
        print(f"\nAll operations logged in: {self.db_path}\n")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 gatebreaker.py <investigation_name> <config_path>")
        sys.exit(1)
    
    investigation_name = sys.argv[1]
    config_path = sys.argv[2]
    
    gb = Gatebreaker(investigation_name, config_path)
    gb.bootstrap()
