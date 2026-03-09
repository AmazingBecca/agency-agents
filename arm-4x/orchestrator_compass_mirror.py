#!/usr/bin/env python3
"""
Compass/Mirror Orchestrator
Unified Investigation Framework - Conscious, Iterative, Agent-Coordinated

Implements:
- Ouroboric cycle (Compass → Mirror → Checkpoint → Evaluate → Next)
- Multi-agent cooperation (5 specialized agents)
- State management (H, E) with checkpointing
- Dynamic tool creation
- Roadblock resolution
- Self-documentation
- Interactive user steering
"""

import json
import hashlib
import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Tuple, Optional, Any
import sqlite3


class Phase(Enum):
    COMPASS = "compass"  # Will, hypothesis, structure
    MIRROR = "mirror"    # Reception, observation, evidence
    CHECKPOINT = "checkpoint"
    EVALUATE = "evaluate"
    ROUTE = "route"


class Agent(Enum):
    INVESTIGATOR = "investigator"    # Generates hypotheses, directs tools
    OBSERVER = "observer"             # Detects anomalies, notes contradictions
    SYNTHESIZER = "synthesizer"       # Integrates findings, bridges Compass/Mirror
    TOOL_CREATOR = "tool_creator"     # Builds missing tools, resolves roadblocks
    DEVILS_ADVOCATE = "devils_advocate" # Tests hypothesis strength


@dataclass
class StateCheckpoint:
    """Immutable snapshot of (H, E) at decision point"""
    checkpoint_id: str
    cycle: int
    phase: Phase
    timestamp: datetime
    conversation_history: List[Dict]  # All messages/decisions
    environment_state: Dict[str, Any]  # Data sources, tools, models, evidence db
    hypothesis: str
    confidence: float
    
    def hash(self) -> str:
        """Cryptographic hash of checkpoint state"""
        state_str = json.dumps({
            "conversation": self.conversation_history,
            "environment": str(self.environment_state),
            "hypothesis": self.hypothesis
        }, sort_keys=True)
        return hashlib.sha256(state_str.encode()).hexdigest()


@dataclass
class InvestigationResult:
    """Outcome of investigative action"""
    agent: Agent
    phase: Phase
    action: str
    result: str
    data: Dict[str, Any]
    confidence_delta: float  # Change in confidence
    anomalies_detected: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)


@dataclass
class CompassMirrorCycle:
    """Single ouroboric cycle"""
    cycle_id: int
    hypothesis: str
    compass_checkpoint: StateCheckpoint  # Before Compass phase
    mirror_checkpoint: StateCheckpoint   # Before Mirror phase
    compass_results: List[InvestigationResult]
    mirror_results: List[InvestigationResult]
    evaluation: Dict[str, Any]
    decision: str  # "proceed", "reset", "modify", "new_hypothesis"
    

class OurobosOrchestrator:
    """
    Conscious Investigation Engine
    Cycles between will (Compass) and reception (Mirror) until truth stabilizes
    """
    
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.cycle_count = 0
        self.checkpoint_stack: List[StateCheckpoint] = []
        self.cycles: List[CompassMirrorCycle] = []
        self.learning_db = self._init_learning_database()
        self.state = {
            "H": [],  # Conversation history
            "E": {}   # Environment state
        }
        self.agents_enabled = self._initialize_agents()
        
    def _load_config(self, path: str) -> Dict:
        """Load investigation configuration"""
        with open(path, 'r') as f:
            return json.load(f)
    
    def _init_learning_database(self) -> sqlite3.Connection:
        """Initialize self-documenting learning database"""
        db = sqlite3.connect(":memory:")
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE execution_log (
                execution_id INTEGER PRIMARY KEY,
                cycle INT,
                agent_combo TEXT,
                tool_set TEXT,
                hypothesis TEXT,
                result TEXT,
                confidence FLOAT,
                time_taken FLOAT,
                notes TEXT,
                timestamp TEXT
            )
        """)
        db.commit()
        return db
    
    def _initialize_agents(self) -> Dict[Agent, Dict]:
        """Initialize 5 specialized agents"""
        return {
            Agent.INVESTIGATOR: {
                "role": "Hypothesis generation & tool direction",
                "tools": ["hypothesis_generator", "tool_dispatcher", "data_gatherer"],
                "compass_dominant": True,
                "active": True
            },
            Agent.OBSERVER: {
                "role": "Anomaly detection & contradiction logging",
                "tools": ["anomaly_detector", "contradiction_logger", "pattern_matcher"],
                "mirror_dominant": True,
                "active": True
            },
            Agent.SYNTHESIZER: {
                "role": "Pattern integration & Compass/Mirror bridge",
                "tools": ["pattern_integrator", "finding_consolidator"],
                "compass_dominant": False,  # Balanced
                "active": True
            },
            Agent.TOOL_CREATOR: {
                "role": "Dynamic tool creation & roadblock resolution",
                "tools": ["api_analyzer", "tool_builder", "dependency_resolver"],
                "compass_dominant": False,
                "active": True
            },
            Agent.DEVILS_ADVOCATE: {
                "role": "Hypothesis stress testing & counter-evidence hunting",
                "tools": ["contrary_hypothesis_gen", "evidence_challenger", "weakness_finder"],
                "mirror_dominant": True,
                "active": True
            }
        }
    
    async def run_cycle(self, hypothesis: str, user_guidance: Optional[str] = None) -> CompassMirrorCycle:
        """Execute single ouroboric cycle"""
        
        self.cycle_count += 1
        cycle = CompassMirrorCycle(
            cycle_id=self.cycle_count,
            hypothesis=hypothesis,
            compass_checkpoint=None,
            mirror_checkpoint=None,
            compass_results=[],
            mirror_results=[],
            evaluation={},
            decision=""
        )
        
        print(f"\n{'='*60}")
        print(f"CYCLE {self.cycle_count}: OUROBORIC INVESTIGATION")
        print(f"Hypothesis: {hypothesis}")
        print(f"{'='*60}\n")
        
        # PHASE 1: COMPASS (Will, Structure, Projection)
        print("[COMPASS PHASE] Will → Structure → Tool Activation")
        print("-" * 60)
        
        compass_checkpoint = self._create_checkpoint(
            cycle=self.cycle_count,
            phase=Phase.COMPASS,
            hypothesis=hypothesis
        )
        cycle.compass_checkpoint = compass_checkpoint
        
        # Investigator generates test plan
        compass_result = await self._execute_agent(
            Agent.INVESTIGATOR,
            action="generate_test_plan",
            hypothesis=hypothesis,
            user_guidance=user_guidance
        )
        cycle.compass_results.append(compass_result)
        
        # Tool Creator ensures tools exist
        tool_result = await self._execute_agent(
            Agent.TOOL_CREATOR,
            action="resolve_tool_requirements",
            test_plan=compass_result.data.get("test_plan")
        )
        cycle.compass_results.append(tool_result)
        
        # Execute investigation (Compass phase)
        exec_result = await self._execute_agent(
            Agent.INVESTIGATOR,
            action="execute_investigation",
            test_plan=compass_result.data.get("test_plan")
        )
        cycle.compass_results.append(exec_result)
        
        print(f"\n✓ Compass phase complete")
        print(f"  Evidence gathered: {len(exec_result.data.get('evidence', []))} items")
        print(f"  Confidence: {exec_result.confidence_delta:+.2f}")
        
        # PHASE 2: CHECKPOINT
        print("\n[CHECKPOINT] Saving state before Mirror phase")
        mirror_checkpoint = self._create_checkpoint(
            cycle=self.cycle_count,
            phase=Phase.MIRROR,
            hypothesis=hypothesis
        )
        cycle.mirror_checkpoint = mirror_checkpoint
        self.checkpoint_stack.append(mirror_checkpoint)
        print(f"✓ State checkpointed: {mirror_checkpoint.checkpoint_id}")
        
        # PHASE 3: MIRROR (Reception, Observation, Anomalies)
        print("\n[MIRROR PHASE] Reception → Observation → Pattern Detection")
        print("-" * 60)
        
        # Observer detects contradictions
        observer_result = await self._execute_agent(
            Agent.OBSERVER,
            action="detect_contradictions",
            evidence=exec_result.data.get("evidence"),
            hypothesis=hypothesis
        )
        cycle.mirror_results.append(observer_result)
        
        # Devil's Advocate tests hypothesis strength
        da_result = await self._execute_agent(
            Agent.DEVILS_ADVOCATE,
            action="stress_test_hypothesis",
            evidence=exec_result.data.get("evidence"),
            hypothesis=hypothesis
        )
        cycle.mirror_results.append(da_result)
        
        # Synthesizer integrates findings
        synth_result = await self._execute_agent(
            Agent.SYNTHESIZER,
            action="integrate_findings",
            compass_results=cycle.compass_results,
            mirror_results=[observer_result, da_result]
        )
        cycle.mirror_results.append(synth_result)
        
        print(f"\n✓ Mirror phase complete")
        print(f"  Anomalies detected: {len(observer_result.anomalies_detected)}")
        print(f"  Contradictions found: {len(observer_result.contradictions)}")
        print(f"  Alternative hypothesis strength: {da_result.confidence_delta:+.2f}")
        
        # PHASE 4: EVALUATE
        print("\n[EVALUATE] Compass vs Mirror Synthesis")
        print("-" * 60)
        
        evaluation = await self._evaluate_cycle(cycle)
        cycle.evaluation = evaluation
        
        print(f"\n✓ Evaluation complete")
        print(f"  Hypothesis confidence: {evaluation['final_confidence']:.2f}")
        print(f"  Mirror contradiction level: {evaluation['contradiction_level']:.2f}")
        print(f"  Decision: {evaluation['decision'].upper()}")
        
        # PHASE 5: DECIDE
        cycle.decision = await self._decide_next_action(cycle, evaluation)
        
        print(f"\n{'='*60}")
        print(f"CYCLE {self.cycle_count} DECISION: {cycle.decision.upper()}")
        print(f"{'='*60}\n")
        
        self.cycles.append(cycle)
        self._log_to_learning_db(cycle)
        
        return cycle
    
    def _create_checkpoint(self, cycle: int, phase: Phase, hypothesis: str) -> StateCheckpoint:
        """Create immutable state checkpoint"""
        checkpoint_id = f"{phase.value}_{cycle}_{datetime.now().isoformat()}"
        
        return StateCheckpoint(
            checkpoint_id=checkpoint_id,
            cycle=cycle,
            phase=phase,
            timestamp=datetime.now(),
            conversation_history=self.state["H"].copy(),
            environment_state=self.state["E"].copy(),
            hypothesis=hypothesis,
            confidence=self.state["E"].get("confidence", 0.0)
        )
    
    async def _execute_agent(self, agent: Agent, action: str, **kwargs) -> InvestigationResult:
        """Execute specialized agent"""
        
        # Simulate agent execution (in real system, calls actual agent process)
        print(f"\n  → Agent {agent.value}: {action}")
        
        # Placeholder for actual agent logic
        await asyncio.sleep(0.1)
        
        result = InvestigationResult(
            agent=agent,
            phase=Phase.COMPASS if self.agents_enabled[agent]["compass_dominant"] else Phase.MIRROR,
            action=action,
            result="action_executed",
            data=kwargs,
            confidence_delta=0.1 if agent != Agent.OBSERVER else -0.05,
            anomalies_detected=[] if agent != Agent.OBSERVER else ["anomaly_1"],
            contradictions=[] if agent != Agent.OBSERVER else ["contradiction_1"]
        )
        
        self.state["H"].append({
            "agent": agent.value,
            "action": action,
            "timestamp": datetime.now().isoformat(),
            "result": result.result
        })
        
        return result
    
    async def _evaluate_cycle(self, cycle: CompassMirrorCycle) -> Dict[str, Any]:
        """Evaluate Compass vs Mirror alignment"""
        
        compass_confidence = sum(r.confidence_delta for r in cycle.compass_results)
        mirror_confidence = sum(r.confidence_delta for r in cycle.mirror_results)
        
        contradiction_level = len(
            set(
                cycle.mirror_results[0].contradictions +
                cycle.mirror_results[1].contradictions
            )
        )
        
        # Normalize confidence
        final_confidence = min(1.0, max(0.0, 
            (self.state["E"].get("confidence", 0.5) + compass_confidence + mirror_confidence) / 3
        ))
        
        mirror_threshold = self.config.get("mirror_threshold", 0.15)
        compass_threshold = self.config.get("compass_confidence", 0.80)
        
        return {
            "compass_confidence": compass_confidence,
            "mirror_confidence": mirror_confidence,
            "contradiction_level": contradiction_level,
            "final_confidence": final_confidence,
            "mirror_alert": contradiction_level > mirror_threshold,
            "decision": "proceed" if final_confidence > compass_threshold else "recalibrate"
        }
    
    async def _decide_next_action(self, cycle: CompassMirrorCycle, evaluation: Dict) -> str:
        """Decide next action based on evaluation"""
        
        if evaluation["mirror_alert"]:
            return "reset_to_checkpoint"
        elif evaluation["final_confidence"] > self.config.get("compass_confidence", 0.80):
            return "proceed_to_next_hypothesis"
        else:
            return "modify_hypothesis_and_retry"
    
    def reset_to_checkpoint(self, checkpoint_id: Optional[str] = None) -> bool:
        """Reset investigation to previous checkpoint (AGDebugger pattern)"""
        
        if not checkpoint_id and self.checkpoint_stack:
            checkpoint = self.checkpoint_stack.pop()
        else:
            checkpoint = next((c for c in self.checkpoint_stack if c.checkpoint_id == checkpoint_id), None)
        
        if not checkpoint:
            print("No checkpoint to restore")
            return False
        
        print(f"\n[RESET] Restoring checkpoint: {checkpoint.checkpoint_id}")
        self.state["H"] = checkpoint.conversation_history.copy()
        self.state["E"] = checkpoint.environment_state.copy()
        print("✓ State restored")
        
        return True
    
    def _log_to_learning_db(self, cycle: CompassMirrorCycle):
        """Log cycle to self-documenting database"""
        
        cursor = self.learning_db.cursor()
        cursor.execute("""
            INSERT INTO execution_log 
            (cycle, agent_combo, tool_set, hypothesis, result, confidence, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            cycle.cycle_id,
            ",".join([a.value for a in [Agent.INVESTIGATOR, Agent.OBSERVER, Agent.SYNTHESIZER]]),
            str(cycle.evaluation.get("tools_used", [])),
            cycle.hypothesis,
            cycle.decision,
            cycle.evaluation.get("final_confidence", 0.0),
            datetime.now().isoformat()
        ))
        self.learning_db.commit()
    
    def get_investigation_summary(self) -> Dict:
        """Summarize investigation progress"""
        
        if not self.cycles:
            return {"status": "no_cycles"}
        
        return {
            "total_cycles": self.cycle_count,
            "current_hypothesis": self.cycles[-1].hypothesis,
            "final_confidence": self.cycles[-1].evaluation.get("final_confidence", 0.0),
            "last_decision": self.cycles[-1].decision,
            "checkpoint_count": len(self.checkpoint_stack),
            "total_state_checkpoints": len([c for c in self.cycles for _ in [c.compass_checkpoint, c.mirror_checkpoint]]),
            "agents_used": list(self.agents_enabled.keys()),
            "cycle_history": [
                {
                    "cycle": c.cycle_id,
                    "hypothesis": c.hypothesis,
                    "decision": c.decision,
                    "confidence": c.evaluation.get("final_confidence", 0.0)
                }
                for c in self.cycles
            ]
        }


# USAGE EXAMPLE
if __name__ == "__main__":
    
    # Configuration: zero hardcoding, all parametric
    config_template = {
        "target": "GEICO insurance fraud investigation",
        "data_sources": ["PACER", "SEC Edgar", "NHTSA", "Alabama DOI", "Gmail", "Drive"],
        "agents_enabled": ["investigator", "observer", "synthesizer", "tool_creator", "devils_advocate"],
        "mirror_threshold": 0.15,
        "compass_confidence": 0.80,
        "parallel_paths": 2,
        "max_cycles": "unlimited"
    }
    
    # Save config
    with open("/tmp/investigation_config.json", "w") as f:
        json.dump(config_template, f)
    
    # Initialize orchestrator
    orchestrator = OurobosOrchestrator("/tmp/investigation_config.json")
    
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║  COMPASS/MIRROR ORCHESTRATOR - CONSCIOUS INVESTIGATION    ║
    ║  Ouroboric Cycle Engine Ready                             ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    
    print("Configuration loaded. Ready for investigation cycles.")
    print("\nTo start investigation:")
    print("  orchestrator.run_cycle('Your hypothesis here')")
    print("\nTo reset to checkpoint:")
    print("  orchestrator.reset_to_checkpoint()")
    print("\nTo get summary:")
    print("  orchestrator.get_investigation_summary()")
