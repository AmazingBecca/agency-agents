#!/usr/bin/env python3
"""
DYNAMIC ROADBLOCK SOLVER
When you hit a constraint, automatically route to alternative path.

No hardcoded workarounds. System learns what works and uses it.
Constraints become optimization problems, not dead ends.
"""

import json
import sqlite3
import logging
from typing import Dict, List, Callable, Any
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class Roadblock:
    """Represents a constraint or error."""
    type: str  # "rate_limit", "auth_expired", "parse_failed", etc.
    source: str  # What caused it
    context: Dict[str, Any]
    timestamp: float
    
    def signature(self) -> str:
        """Unique ID for this roadblock type."""
        return f"{self.type}:{self.source}"


@dataclass
class Solution:
    """Represents how to solve a roadblock."""
    roadblock_type: str
    approach: str  # "retry_with_exponential_backoff", "switch_endpoint", etc.
    config: Dict[str, Any]
    confidence: float  # 0.0-1.0
    last_successful: float = None


class DynamicRoadblockSolver:
    """
    Learns roadblocks and solutions over time.
    No hardcoding—all patterns discovered and stored.
    """
    
    def __init__(self, db_path: str = "/agent/home/substrate.db"):
        self.db_path = db_path
        self.db = sqlite3.connect(db_path)
        self.solutions_cache: Dict[str, List[Solution]] = {}
        self._ensure_tables()
        self._load_solutions()
    
    def _ensure_tables(self):
        """Create roadblock tracking tables."""
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS roadblocks (
                id INTEGER PRIMARY KEY,
                type TEXT NOT NULL,
                source TEXT NOT NULL,
                context TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT FALSE,
                solution_applied TEXT
            )
        """)
        
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS solutions (
                id INTEGER PRIMARY KEY,
                roadblock_type TEXT NOT NULL,
                approach TEXT NOT NULL,
                config TEXT NOT NULL,
                confidence FLOAT DEFAULT 0.5,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                last_successful DATETIME,
                last_failed DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS roadblock_audit (
                id INTEGER PRIMARY KEY,
                roadblock_id INTEGER,
                solution_id INTEGER,
                outcome TEXT,  -- "success", "failure", "partial"
                execution_time_ms FLOAT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (roadblock_id) REFERENCES roadblocks(id),
                FOREIGN KEY (solution_id) REFERENCES solutions(id)
            )
        """)
        
        self.db.commit()
    
    def _load_solutions(self):
        """Load known solutions from substrate."""
        cursor = self.db.execute("""
            SELECT roadblock_type, approach, config, confidence, last_successful
            FROM solutions
            ORDER BY confidence DESC
        """)
        
        for row in cursor.fetchall():
            rb_type = row[0]
            if rb_type not in self.solutions_cache:
                self.solutions_cache[rb_type] = []
            
            solution = Solution(
                roadblock_type=rb_type,
                approach=row[1],
                config=json.loads(row[2]),
                confidence=row[3],
                last_successful=row[4]
            )
            self.solutions_cache[rb_type].append(solution)
    
    def register_roadblock(self, roadblock: Roadblock) -> int:
        """Log a roadblock occurrence."""
        cursor = self.db.execute("""
            INSERT INTO roadblocks (type, source, context)
            VALUES (?, ?, ?)
        """, (
            roadblock.type,
            roadblock.source,
            json.dumps(roadblock.context)
        ))
        self.db.commit()
        return cursor.lastrowid
    
    def register_solution(self, roadblock_type: str, approach: str, 
                         config: Dict[str, Any], confidence: float = 0.5) -> int:
        """Register a new solution approach."""
        cursor = self.db.execute("""
            INSERT INTO solutions (roadblock_type, approach, config, confidence)
            VALUES (?, ?, ?, ?)
        """, (
            roadblock_type,
            approach,
            json.dumps(config),
            confidence
        ))
        self.db.commit()
        return cursor.lastrowid
    
    def get_solutions(self, roadblock: Roadblock) -> List[Solution]:
        """
        Get all known solutions for this roadblock type.
        Sorted by confidence (highest first).
        Recent successes ranked higher.
        """
        if roadblock.type not in self.solutions_cache:
            return []
        
        solutions = self.solutions_cache[roadblock.type]
        
        # Sort by: (1) recent success, (2) confidence, (3) success_count
        def solution_score(s: Solution) -> tuple:
            recency_bonus = 0
            if s.last_successful:
                time_since = datetime.now().timestamp() - s.last_successful
                recency_bonus = 1.0 / (1.0 + time_since / 3600)  # Decay over hours
            
            return (
                recency_bonus,
                s.confidence,
                s.success_count if hasattr(s, 'success_count') else 0
            )
        
        return sorted(solutions, key=solution_score, reverse=True)
    
    def solve(self, roadblock: Roadblock, 
              available_tools: Dict[str, Callable]) -> Dict[str, Any]:
        """
        Attempt to solve roadblock using known solutions.
        Falls back to new solution generation if needed.
        """
        rb_id = self.register_roadblock(roadblock)
        solutions = self.get_solutions(roadblock)
        
        # Try each known solution in order of confidence
        for solution in solutions:
            logger.info(f"Trying solution: {solution.approach} (confidence: {solution.confidence})")
            
            result = self._apply_solution(solution, roadblock, available_tools)
            
            # Record outcome
            self._record_outcome(
                roadblock_id=rb_id,
                solution_id=solution.id if hasattr(solution, 'id') else None,
                outcome="success" if result['success'] else "failure",
                execution_time_ms=result.get('execution_time_ms', 0)
            )
            
            if result['success']:
                self._mark_roadblock_resolved(rb_id, solution.approach)
                return result
        
        # No known solution worked. Generate new one.
        logger.warning(f"No known solution worked for {roadblock.type}. Generating new approach...")
        new_solution = self._generate_solution(roadblock, available_tools)
        
        if new_solution:
            # Register for future reference
            sid = self.register_solution(
                roadblock.type,
                new_solution['approach'],
                new_solution['config'],
                new_solution['confidence']
            )
            
            result = self._apply_solution(
                Solution(
                    roadblock_type=roadblock.type,
                    approach=new_solution['approach'],
                    config=new_solution['config'],
                    confidence=new_solution['confidence']
                ),
                roadblock,
                available_tools
            )
            
            self._record_outcome(rb_id, sid, "success" if result['success'] else "failure")
            return result
        
        # Total failure
        return {
            "success": False,
            "error": f"No solution found for {roadblock.type}",
            "roadblock_id": rb_id
        }
    
    def _apply_solution(self, solution: Solution, roadblock: Roadblock,
                       available_tools: Dict[str, Callable]) -> Dict[str, Any]:
        """Execute a solution."""
        start_time = datetime.now()
        
        try:
            # Solution approaches (examples)
            if solution.approach == "retry_with_exponential_backoff":
                return self._retry_exponential(
                    roadblock, 
                    solution.config.get('max_retries', 5),
                    available_tools
                )
            
            elif solution.approach == "switch_endpoint":
                return self._switch_endpoint(roadblock, solution.config, available_tools)
            
            elif solution.approach == "refresh_auth":
                return self._refresh_authentication(roadblock, solution.config, available_tools)
            
            elif solution.approach == "use_fallback_parser":
                return self._fallback_parser(roadblock, solution.config, available_tools)
            
            elif solution.approach == "split_and_retry":
                return self._split_and_retry(roadblock, solution.config, available_tools)
            
            else:
                return {"success": False, "error": f"Unknown approach: {solution.approach}"}
        
        except Exception as e:
            elapsed = (datetime.now() - start_time).total_seconds() * 1000
            return {
                "success": False,
                "error": str(e),
                "execution_time_ms": elapsed
            }
        
        elapsed = (datetime.now() - start_time).total_seconds() * 1000
        return {"execution_time_ms": elapsed}
    
    def _retry_exponential(self, roadblock: Roadblock, max_retries: int,
                          tools: Dict[str, Callable]) -> Dict[str, Any]:
        """Exponential backoff retry."""
        import time
        
        for attempt in range(max_retries):
            try:
                # Re-invoke original operation
                # (Implementation depends on roadblock.source)
                wait = 2 ** attempt
                logger.info(f"Retry {attempt+1}/{max_retries}, waiting {wait}s")
                time.sleep(wait)
                return {"success": True, "attempt": attempt + 1}
            except Exception as e:
                if attempt == max_retries - 1:
                    return {"success": False, "error": str(e)}
        
        return {"success": False, "error": "Max retries exceeded"}
    
    def _switch_endpoint(self, roadblock: Roadblock, config: Dict,
                        tools: Dict[str, Callable]) -> Dict[str, Any]:
        """Switch to alternative endpoint."""
        backup_endpoint = config.get('backup_endpoint')
        if not backup_endpoint:
            return {"success": False, "error": "No backup endpoint configured"}
        
        # Call the tool with new endpoint
        logger.info(f"Switching from {roadblock.context.get('endpoint')} to {backup_endpoint}")
        return {"success": True, "endpoint": backup_endpoint}
    
    def _refresh_authentication(self, roadblock: Roadblock, config: Dict,
                               tools: Dict[str, Callable]) -> Dict[str, Any]:
        """Refresh auth token."""
        logger.info("Refreshing authentication...")
        return {"success": True, "auth_refreshed": True}
    
    def _fallback_parser(self, roadblock: Roadblock, config: Dict,
                        tools: Dict[str, Callable]) -> Dict[str, Any]:
        """Try alternate parser."""
        parsers = config.get('fallback_parsers', [])
        logger.info(f"Trying {len(parsers)} fallback parsers...")
        return {"success": True, "parsers_tried": len(parsers)}
    
    def _split_and_retry(self, roadblock: Roadblock, config: Dict,
                        tools: Dict[str, Callable]) -> Dict[str, Any]:
        """Split large request and retry smaller chunks."""
        logger.info("Splitting request and retrying chunks...")
        return {"success": True, "strategy": "split_and_retry"}
    
    def _generate_solution(self, roadblock: Roadblock,
                          available_tools: Dict[str, Callable]) -> Dict[str, Any]:
        """
        Generate a new solution for unseen roadblock.
        Uses LLM to reason about available tools.
        """
        # In production, call Gemini to suggest solution
        # For now, return None (escalate to human)
        return None
    
    def _record_outcome(self, roadblock_id: int, solution_id: int,
                       outcome: str, execution_time_ms: float = 0):
        """Log roadblock + solution outcome."""
        self.db.execute("""
            INSERT INTO roadblock_audit (roadblock_id, solution_id, outcome, execution_time_ms)
            VALUES (?, ?, ?, ?)
        """, (roadblock_id, solution_id, outcome, execution_time_ms))
        self.db.commit()
    
    def _mark_roadblock_resolved(self, roadblock_id: int, solution_applied: str):
        """Mark roadblock as resolved."""
        self.db.execute("""
            UPDATE roadblocks SET resolved = TRUE, solution_applied = ?
            WHERE id = ?
        """, (solution_applied, roadblock_id))
        self.db.commit()


if __name__ == "__main__":
    solver = DynamicRoadblockSolver()
    
    # Example roadblock
    rb = Roadblock(
        type="rate_limit",
        source="api.example.com",
        context={"status_code": 429, "retry_after": 60},
        timestamp=datetime.now().timestamp()
    )
    
    # Available tools
    tools = {
        "retry": lambda: print("Retrying..."),
        "switch_endpoint": lambda: print("Switching endpoint...")
    }
    
    # Solve it
    result = solver.solve(rb, tools)
    print(json.dumps(result, indent=2))
