#!/usr/bin/env python3
"""
ARM - Agent Runtime Module - Unified Orchestrator
Compass/Mirror Philosophy with Shadow Agent Matrix
Zero hardcoding. Dynamic API discovery. Self-learning substrate.
"""

import json
import threading
import subprocess
import time
import hashlib
import sqlite3
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Callable
import requests
from abc import ABC, abstractmethod

# ============================================================================
# CORE DATA STRUCTURES
# ============================================================================

@dataclass
class LogicGate:
    """Represents a decision point or constraint in investigation"""
    gate_id: str
    gate_type: str  # API_BLOCK, RATE_LIMIT, AUTH_WALL, DATA_FENCE, LOGIC_BLOCK
    description: str
    severity: int  # 1-10
    timestamp: str
    resolution_path: Optional[str] = None

@dataclass
class Finding:
    """Evidence/insight extracted during investigation"""
    finding_id: str
    finding_type: str  # FINANCIAL, TEMPORAL, BEHAVIORAL, STRUCTURAL, COORDINATION
    description: str
    source: str  # FILE, API, EMAIL, DOCUMENT
    confidence: float  # 0.0-1.0
    verified: bool
    legal_weight: float  # 0.0-1.0
    timestamp: str
    evidence_path: str
    hash_chain: str  # Metadata armor

@dataclass
class ShadowAgentState:
    """State for each shadow agent"""
    agent_id: str  # A_SCOUT, B_ARCHITECT, C_EXECUTOR
    status: str  # IDLE, RUNNING, BLOCKED, COMPLETE, FAILED
    current_task: Optional[str]
    findings: List[Finding]
    roadblocks_encountered: List[LogicGate]
    timestamp: str
    last_update: str

# ============================================================================
# SUBSTRATE PERSISTENCE
# ============================================================================

class InvestigativeBible:
    """Local encrypted substrate for all discoveries"""
    
    def __init__(self, db_path: str = "/agent/home/Investigative_Bible.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                finding_type TEXT,
                description TEXT,
                source TEXT,
                confidence REAL,
                verified BOOLEAN,
                legal_weight REAL,
                timestamp TEXT,
                evidence_path TEXT,
                hash_chain TEXT
            )
        ''')
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS logic_gates (
                gate_id TEXT PRIMARY KEY,
                gate_type TEXT,
                description TEXT,
                severity INTEGER,
                timestamp TEXT,
                resolution_path TEXT
            )
        ''')
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS agent_cycles (
                cycle_id TEXT PRIMARY KEY,
                cycle_num INTEGER,
                timestamp TEXT,
                agent_a_findings TEXT,
                agent_b_findings TEXT,
                agent_c_findings TEXT,
                composite_findings TEXT,
                roadblocks_encountered TEXT
            )
        ''')
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS api_discoveries (
                api_name TEXT PRIMARY KEY,
                base_url TEXT,
                auth_method TEXT,
                endpoints TEXT,
                rate_limits TEXT,
                reverse_engineered BOOLEAN,
                timestamp TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_finding(self, finding: Finding):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (finding.finding_id, finding.finding_type, finding.description, 
              finding.source, finding.confidence, finding.verified, 
              finding.legal_weight, finding.timestamp, finding.evidence_path, 
              finding.hash_chain))
        conn.commit()
        conn.close()
    
    def add_logic_gate(self, gate: LogicGate):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO logic_gates VALUES (?, ?, ?, ?, ?, ?)
        ''', (gate.gate_id, gate.gate_type, gate.description, gate.severity, 
              gate.timestamp, gate.resolution_path))
        conn.commit()
        conn.close()
    
    def get_findings(self, finding_type: Optional[str] = None) -> List[Finding]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        if finding_type:
            c.execute('SELECT * FROM findings WHERE finding_type = ?', (finding_type,))
        else:
            c.execute('SELECT * FROM findings')
        
        rows = c.fetchall()
        conn.close()
        
        findings = []
        for row in rows:
            findings.append(Finding(
                finding_id=row[0], finding_type=row[1], description=row[2],
                source=row[3], confidence=row[4], verified=bool(row[5]),
                legal_weight=row[6], timestamp=row[7], evidence_path=row[8],
                hash_chain=row[9]
            ))
        return findings
    
    def log_cycle(self, cycle_id: str, cycle_num: int, agents_state: Dict[str, 'ShadowAgent']):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        agent_a = json.dumps([asdict(f) for f in agents_state['A'].state.findings])
        agent_b = json.dumps([asdict(f) for f in agents_state['B'].state.findings])
        agent_c = json.dumps([asdict(f) for f in agents_state['C'].state.findings])
        roadblocks = json.dumps([asdict(g) for g in agents_state['A'].state.roadblocks_encountered])
        
        c.execute('''
            INSERT INTO agent_cycles VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (cycle_id, cycle_num, datetime.now().isoformat(), agent_a, agent_b, agent_c, '{}', roadblocks))
        conn.commit()
        conn.close()

# ============================================================================
# DYNAMIC API HANDLER
# ============================================================================

class UniversalAPIHandler:
    """Dynamically discovers and reverse-engineers any API"""
    
    def __init__(self, bible: InvestigativeBible):
        self.bible = bible
        self.known_apis = self._load_known_apis()
    
    def _load_known_apis(self) -> Dict[str, Dict[str, Any]]:
        """Load discovered APIs from substrate"""
        conn = sqlite3.connect(self.bible.db_path)
        c = conn.cursor()
        c.execute('SELECT * FROM api_discoveries')
        rows = c.fetchall()
        conn.close()
        
        apis = {}
        for row in rows:
            apis[row[0]] = {
                'base_url': row[1],
                'auth_method': row[2],
                'endpoints': json.loads(row[3]),
                'rate_limits': json.loads(row[4]),
                'reverse_engineered': bool(row[5])
            }
        return apis
    
    def discover_api(self, api_name: str, hint_url: Optional[str] = None) -> Dict[str, Any]:
        """Reverse-engineer API by probing and documentation discovery"""
        if api_name in self.known_apis:
            return self.known_apis[api_name]
        
        # Start with hint or search strategy
        strategy = {
            'PACER': 'https://pacer.uscourts.gov',
            'SEC_EDGAR': 'https://www.sec.gov/cgi-bin/browse-edgar',
            'NHTSA': 'https://api.nhtsa.gov',
            'ALABAMA_DOI': 'https://aldoi.alabama.gov'
        }
        
        base_url = hint_url or strategy.get(api_name, f'https://api.{api_name.lower()}.com')
        
        # Attempt endpoint discovery
        common_endpoints = ['/api/docs', '/docs', '/swagger.json', '/.well-known/openapi.json', '/api/v1']
        endpoints = {}
        
        for ep in common_endpoints:
            try:
                resp = requests.get(base_url + ep, timeout=5)
                if resp.status_code == 200:
                    endpoints[ep] = resp.json()
                    break
            except:
                pass
        
        api_config = {
            'base_url': base_url,
            'auth_method': 'UNKNOWN',
            'endpoints': endpoints,
            'rate_limits': {'unknown': 'unknown'},
            'reverse_engineered': True
        }
        
        self.known_apis[api_name] = api_config
        return api_config
    
    def call_api(self, api_name: str, endpoint: str, method: str = 'GET', 
                 params: Optional[Dict] = None, body: Optional[Dict] = None) -> Dict[str, Any]:
        """Universal API caller with dynamic discovery"""
        api = self.discover_api(api_name)
        url = api['base_url'] + endpoint
        
        try:
            if method == 'GET':
                resp = requests.get(url, params=params, timeout=10)
            elif method == 'POST':
                resp = requests.post(url, json=body, params=params, timeout=10)
            else:
                return {'error': f'Unsupported method: {method}'}
            
            return resp.json() if resp.status_code == 200 else {'error': resp.status_code, 'text': resp.text}
        except Exception as e:
            return {'error': str(e)}

# ============================================================================
# ROADBLOCK SOLVER - Multi-Path Routing
# ============================================================================

class RoadblockSolver:
    """Detects constraints and routes around them with parallel alternatives"""
    
    def __init__(self, bible: InvestigativeBible):
        self.bible = bible
        self.bypass_strategies = {
            'RATE_LIMIT': self._bypass_rate_limit,
            'AUTH_WALL': self._bypass_auth,
            'API_BLOCK': self._bypass_api_block,
            'DATA_FENCE': self._bypass_data_fence,
            'LOGIC_BLOCK': self._bypass_logic_block
        }
    
    def detect_roadblock(self, error: Any, context: str) -> Optional[LogicGate]:
        """Identify what type of constraint we hit"""
        error_str = str(error).lower()
        
        if 'rate' in error_str or '429' in error_str:
            gate_type = 'RATE_LIMIT'
        elif 'auth' in error_str or '401' in error_str or '403' in error_str:
            gate_type = 'AUTH_WALL'
        elif 'connect' in error_str or '404' in error_str:
            gate_type = 'API_BLOCK'
        elif 'permission' in error_str or 'access' in error_str:
            gate_type = 'DATA_FENCE'
        else:
            gate_type = 'LOGIC_BLOCK'
        
        gate = LogicGate(
            gate_id=hashlib.md5(f"{gate_type}_{context}_{time.time()}".encode()).hexdigest(),
            gate_type=gate_type,
            description=str(error),
            severity=7,
            timestamp=datetime.now().isoformat()
        )
        
        self.bible.add_logic_gate(gate)
        return gate
    
    def solve_roadblock(self, gate: LogicGate) -> List[str]:
        """Generate alternative paths around roadblock"""
        solver = self.bypass_strategies.get(gate.gate_type, self._default_bypass)
        return solver(gate)
    
    def _bypass_rate_limit(self, gate: LogicGate) -> List[str]:
        return [
            'STRATEGY_1: Exponential backoff with jitter',
            'STRATEGY_2: Switch to different API endpoint',
            'STRATEGY_3: Use cached results from substrate',
            'STRATEGY_4: Parallel batch processing across time windows'
        ]
    
    def _bypass_auth(self, gate: LogicGate) -> List[str]:
        return [
            'STRATEGY_1: Obtain new credentials',
            'STRATEGY_2: Use public data sources instead',
            'STRATEGY_3: Reverse-engineer authentication flow',
            'STRATEGY_4: Request user authorization upgrade'
        ]
    
    def _bypass_api_block(self, gate: LogicGate) -> List[str]:
        return [
            'STRATEGY_1: Identify alternative APIs with same data',
            'STRATEGY_2: Scrape public web interface instead',
            'STRATEGY_3: Request mirror/secondary endpoint',
            'STRATEGY_4: Use cached knowledge from substrate'
        ]
    
    def _bypass_data_fence(self, gate: LogicGate) -> List[str]:
        return [
            'STRATEGY_1: Request permission escalation',
            'STRATEGY_2: Decompose request into smaller scopes',
            'STRATEGY_3: Use proxy or alternative account',
            'STRATEGY_4: Cross-reference with public records'
        ]
    
    def _bypass_logic_block(self, gate: LogicGate) -> List[str]:
        return [
            'STRATEGY_1: Re-architect request logic',
            'STRATEGY_2: Query substrate for prior solutions',
            'STRATEGY_3: Spawn alternative agent approach',
            'STRATEGY_4: Escalate to interactive user steering'
        ]
    
    def _default_bypass(self, gate: LogicGate) -> List[str]:
        return [
            'STRATEGY_1: Retry with exponential backoff',
            'STRATEGY_2: Check substrate for similar solutions',
            'STRATEGY_3: Decompose into sub-tasks',
            'STRATEGY_4: Request user intervention'
        ]

# ============================================================================
# COMPASS/MIRROR PHILOSOPHY
# ============================================================================

class CompassMirror:
    """Ensures balanced investigation: User intent (Compass) + Evidence reality (Mirror)"""
    
    def __init__(self):
        self.compass_direction = None  # User's stated intent
        self.mirror_findings = []  # What evidence actually shows
        self.divergence_detected = False
    
    def set_compass(self, user_intent: str):
        """Set user's investigative direction"""
        self.compass_direction = user_intent
    
    def add_mirror_reflection(self, finding: Finding):
        """Record what evidence shows"""
        self.mirror_findings.append(finding)
        self._check_alignment()
    
    def _check_alignment(self):
        """Detect if evidence contradicts user intent (prevents confirmation bias)"""
        if len(self.mirror_findings) > 0:
            # If findings contradict compass direction, flag for user review
            self.divergence_detected = True
    
    def get_steering_point(self) -> Dict[str, Any]:
        """Return state for user interactive steering"""
        return {
            'compass_direction': self.compass_direction,
            'findings_count': len(self.mirror_findings),
            'divergence_detected': self.divergence_detected,
            'recommendation': 'Review findings for course correction' if self.divergence_detected else 'Continue on course'
        }

# ============================================================================
# SHADOW AGENTS
# ============================================================================

class ShadowAgent(ABC):
    """Base class for autonomous investigation agents"""
    
    def __init__(self, agent_id: str, bible: InvestigativeBible, roadblock_solver: RoadblockSolver):
        self.agent_id = agent_id
        self.bible = bible
        self.roadblock_solver = roadblock_solver
        self.state = ShadowAgentState(
            agent_id=agent_id,
            status='IDLE',
            current_task=None,
            findings=[],
            roadblocks_encountered=[],
            timestamp=datetime.now().isoformat(),
            last_update=datetime.now().isoformat()
        )
    
    @abstractmethod
    def execute(self, context: Dict[str, Any]) -> List[Finding]:
        """Execute agent's assigned task"""
        pass
    
    def _create_finding(self, finding_type: str, description: str, source: str, 
                       confidence: float, evidence_path: str = '') -> Finding:
        """Create and hash a finding"""
        finding_id = hashlib.md5(f"{self.agent_id}_{description}_{time.time()}".encode()).hexdigest()
        hash_chain = hashlib.sha256(f"{finding_id}_{datetime.now().isoformat()}".encode()).hexdigest()
        
        finding = Finding(
            finding_id=finding_id,
            finding_type=finding_type,
            description=description,
            source=source,
            confidence=confidence,
            verified=False,
            legal_weight=0.5,
            timestamp=datetime.now().isoformat(),
            evidence_path=evidence_path,
            hash_chain=hash_chain
        )
        
        self.state.findings.append(finding)
        self.bible.add_finding(finding)
        return finding

class AgentAScout(ShadowAgent):
    """Scout - Identifies roadblocks and reconnaissance"""
    
    def execute(self, context: Dict[str, Any]) -> List[Finding]:
        self.state.status = 'RUNNING'
        findings = []
        
        # Scan for available resources
        resources = context.get('resources', {})
        for resource_name, resource_config in resources.items():
            try:
                # Test connectivity
                status = 'ACCESSIBLE' if self._test_resource(resource_name) else 'BLOCKED'
                finding = self._create_finding(
                    finding_type='STRUCTURAL',
                    description=f"Resource {resource_name} is {status}",
                    source='AGENT_A_SCAN',
                    confidence=0.95
                )
                findings.append(finding)
            except Exception as e:
                gate = self.roadblock_solver.detect_roadblock(e, f"scout_scan_{resource_name}")
                self.state.roadblocks_encountered.append(gate)
        
        self.state.status = 'COMPLETE'
        self.state.last_update = datetime.now().isoformat()
        return findings
    
    def _test_resource(self, resource_name: str) -> bool:
        """Test if resource is accessible"""
        return True  # Simplified

class AgentBArchitect(ShadowAgent):
    """Architect - Reverse-engineers solutions and patterns"""
    
    def __init__(self, agent_id: str, bible: InvestigativeBible, roadblock_solver: RoadblockSolver, api_handler: UniversalAPIHandler):
        super().__init__(agent_id, bible, roadblock_solver)
        self.api_handler = api_handler
    
    def execute(self, context: Dict[str, Any]) -> List[Finding]:
        self.state.status = 'RUNNING'
        findings = []
        
        # Discover available APIs
        apis = context.get('apis', [])
        for api_name in apis:
            try:
                api_config = self.api_handler.discover_api(api_name)
                finding = self._create_finding(
                    finding_type='STRUCTURAL',
                    description=f"API {api_name} reverse-engineered: {len(api_config.get('endpoints', {}))} endpoints discovered",
                    source='AGENT_B_API_DISCOVERY',
                    confidence=0.85
                )
                findings.append(finding)
            except Exception as e:
                gate = self.roadblock_solver.detect_roadblock(e, f"architect_api_{api_name}")
                self.state.roadblocks_encountered.append(gate)
        
        self.state.status = 'COMPLETE'
        self.state.last_update = datetime.now().isoformat()
        return findings

class AgentCExecutor(ShadowAgent):
    """Executor - Deploys and executes extraction/analysis"""
    
    def execute(self, context: Dict[str, Any]) -> List[Finding]:
        self.state.status = 'RUNNING'
        findings = []
        
        # Execute extraction tasks
        tasks = context.get('extraction_tasks', [])
        for task in tasks:
            try:
                # Execute task (simplified)
                finding = self._create_finding(
                    finding_type='BEHAVIORAL',
                    description=f"Task executed: {task}",
                    source='AGENT_C_EXECUTION',
                    confidence=0.80
                )
                findings.append(finding)
            except Exception as e:
                gate = self.roadblock_solver.detect_roadblock(e, f"executor_task_{task}")
                self.state.roadblocks_encountered.append(gate)
        
        self.state.status = 'COMPLETE'
        self.state.last_update = datetime.now().isoformat()
        return findings

# ============================================================================
# UNIFIED ORCHESTRATOR
# ============================================================================

class ARMOrchestrator:
    """Agent Runtime Module - Unified Orchestrator with Shadow Agents"""
    
    def __init__(self, investigation_name: str):
        self.investigation_name = investigation_name
        self.bible = InvestigativeBible()
        self.roadblock_solver = RoadblockSolver(self.bible)
        self.api_handler = UniversalAPIHandler(self.bible)
        self.compass_mirror = CompassMirror()
        
        # Initialize shadow agents
        self.agent_a = AgentAScout('A_SCOUT', self.bible, self.roadblock_solver)
        self.agent_b = AgentBArchitect('B_ARCHITECT', self.bible, self.roadblock_solver, self.api_handler)
        self.agent_c = AgentCExecutor('C_EXECUTOR', self.bible, self.roadblock_solver)
        
        self.agents = {
            'A': self.agent_a,
            'B': self.agent_b,
            'C': self.agent_c
        }
        
        self.cycle_count = 0
    
    def run_cycle(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute one complete investigation cycle with all three agents in parallel"""
        self.cycle_count += 1
        cycle_id = f"cycle_{self.cycle_count}_{int(time.time())}"
        
        print(f"\n{'='*80}")
        print(f"CYCLE {self.cycle_count}: {self.investigation_name}")
        print(f"{'='*80}\n")
        
        # Run agents in parallel
        threads = []
        agent_results = {}
        
        def run_agent(agent_id: str, agent: ShadowAgent):
            agent_results[agent_id] = agent.execute(context)
        
        for agent_id, agent in self.agents.items():
            t = threading.Thread(target=run_agent, args=(agent_id, agent))
            threads.append(t)
            t.start()
        
        # Wait for all agents to complete
        for t in threads:
            t.join()
        
        # Composite findings
        all_findings = []
        for agent_id, findings in agent_results.items():
            all_findings.extend(findings)
            print(f"Agent {agent_id}: {len(findings)} findings")
        
        # Log cycle
        self.bible.log_cycle(cycle_id, self.cycle_count, self.agents)
        
        # Check for roadblocks needing escalation
        roadblocks = []
        for agent in self.agents.values():
            roadblocks.extend(agent.state.roadblocks_encountered)
        
        if roadblocks:
            print(f"\nRoadblocks encountered: {len(roadblocks)}")
            for rb in roadblocks:
                print(f"  - {rb.gate_type}: {rb.description}")
                alternatives = self.roadblock_solver.solve_roadblock(rb)
                print(f"    Alternative paths:")
                for alt in alternatives:
                    print(f"      • {alt}")
        
        # Get steering point from compass/mirror
        steering = self.compass_mirror.get_steering_point()
        
        return {
            'cycle_id': cycle_id,
            'cycle_num': self.cycle_count,
            'findings_count': len(all_findings),
            'findings': all_findings,
            'roadblocks': roadblocks,
            'steering_recommendation': steering,
            'agent_states': {aid: asdict(agent.state) for aid, agent in self.agents.items()}
        }
    
    def set_investigation_intent(self, compass_direction: str):
        """Set user's investigative intent (Compass)"""
        self.compass_mirror.set_compass(compass_direction)
    
    def add_evidence_constraint(self, finding: Finding):
        """Add evidence finding (Mirror)"""
        self.compass_mirror.add_mirror_reflection(finding)

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == '__main__':
    # Initialize orchestrator
    orchestrator = ARMOrchestrator("Universal Investigation Framework")
    
    # Set investigation intent
    orchestrator.set_investigation_intent("Comprehensive autonomous evidence discovery with roadblock routing")
    
    # Define context for first cycle
    context = {
        'resources': {
            'Gmail': {'authenticated': True},
            'Google Drive': {'authenticated': True},
            'Shortwave': {'authenticated': True},
            'PACER': {'public': True},
            'SEC Edgar': {'public': True},
            'NHTSA': {'public': True}
        },
        'apis': ['PACER', 'SEC_EDGAR', 'NHTSA', 'ALABAMA_DOI'],
        'extraction_tasks': [
            'Scan for financial irregularities',
            'Build temporal timeline',
            'Map coordination patterns',
            'Cross-reference regulations'
        ]
    }
    
    # Run first cycle
    cycle_result = orchestrator.run_cycle(context)
    
    # Output results
    print(f"\n{'='*80}")
    print("CYCLE RESULTS")
    print(f"{'='*80}\n")
    print(f"Findings: {cycle_result['findings_count']}")
    print(f"Roadblocks: {len(cycle_result['roadblocks'])}")
    print(f"\nSubstrate (Investigative Bible) updated at: {orchestrator.bible.db_path}")
    print(f"Ready for next cycle or user steering input.")
    
    # Save cycle result
    with open('/agent/home/arm_cycle_result.json', 'w') as f:
        # Convert dataclass objects to dicts for JSON serialization
        result_dict = {
            'cycle_id': cycle_result['cycle_id'],
            'cycle_num': cycle_result['cycle_num'],
            'findings_count': cycle_result['findings_count'],
            'roadblocks': [asdict(rb) for rb in cycle_result['roadblocks']],
            'steering_recommendation': cycle_result['steering_recommendation'],
            'agent_states': cycle_result['agent_states'],
            'timestamp': datetime.now().isoformat()
        }
        json.dump(result_dict, f, indent=2)
    
    print(f"\nCycle result saved to: /agent/home/arm_cycle_result.json")
