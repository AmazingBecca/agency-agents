#!/usr/bin/env python3
"""
SELF-DOCUMENTING FRAMEWORK
System learns what works and documents itself.

Every API call, every pattern, every success is documented.
Next time, system knows what to do without being told.
"""

import json
import sqlite3
import hashlib
from typing import Dict, Any, List, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class APIPattern:
    """Represents a learned API pattern."""
    endpoint: str
    method: str
    required_params: List[str]
    optional_params: List[str]
    auth_type: str
    response_schema: Dict[str, Any]
    request_headers: Dict[str, str]
    success_rate: float
    last_used: datetime
    call_count: int
    documentation: str  # User-readable description


@dataclass
class ExecutionTrace:
    """Records a single execution for learning."""
    task_id: str
    operation: str
    input_params: Dict[str, Any]
    output_data: Dict[str, Any]
    success: bool
    execution_time_ms: float
    timestamp: datetime


class SelfDocumentingFramework:
    """
    System that learns from every execution and documents patterns.
    """
    
    def __init__(self, db_path: str = "/agent/home/substrate.db"):
        self.db_path = db_path
        self.db = sqlite3.connect(db_path)
        self.patterns: Dict[str, APIPattern] = {}
        self._ensure_tables()
        self._load_patterns()
    
    def _ensure_tables(self):
        """Create documentation tables."""
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS execution_traces (
                id INTEGER PRIMARY KEY,
                task_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                input_hash TEXT NOT NULL,
                output_hash TEXT NOT NULL,
                input_params TEXT,
                output_data TEXT,
                success BOOLEAN,
                execution_time_ms FLOAT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS learned_patterns (
                id INTEGER PRIMARY KEY,
                endpoint TEXT UNIQUE,
                method TEXT,
                required_params TEXT,
                optional_params TEXT,
                auth_type TEXT,
                response_schema TEXT,
                request_headers TEXT,
                success_rate FLOAT,
                call_count INTEGER DEFAULT 0,
                last_used DATETIME,
                first_discovered DATETIME DEFAULT CURRENT_TIMESTAMP,
                documentation TEXT
            )
        """)
        
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS pattern_variations (
                id INTEGER PRIMARY KEY,
                pattern_id INTEGER,
                variation_name TEXT,
                params_used TEXT,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (pattern_id) REFERENCES learned_patterns(id)
            )
        """)
        
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS generated_docs (
                id INTEGER PRIMARY KEY,
                pattern_id INTEGER,
                doc_format TEXT,  -- "markdown", "json_schema", "curl_example"
                content TEXT,
                generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (pattern_id) REFERENCES learned_patterns(id)
            )
        """)
        
        self.db.commit()
    
    def _load_patterns(self):
        """Load learned patterns from substrate."""
        cursor = self.db.execute("""
            SELECT endpoint, method, required_params, optional_params,
                   auth_type, response_schema, request_headers, success_rate,
                   last_used, call_count, documentation
            FROM learned_patterns
            ORDER BY call_count DESC
        """)
        
        for row in cursor.fetchall():
            pattern = APIPattern(
                endpoint=row[0],
                method=row[1],
                required_params=json.loads(row[2]),
                optional_params=json.loads(row[3]),
                auth_type=row[4],
                response_schema=json.loads(row[5]),
                request_headers=json.loads(row[6]),
                success_rate=row[7],
                last_used=row[8],
                call_count=row[9],
                documentation=row[10]
            )
            self.patterns[row[0]] = pattern
    
    def record_execution(self, trace: ExecutionTrace):
        """Record an execution for learning."""
        input_hash = hashlib.sha256(
            json.dumps(trace.input_params, sort_keys=True).encode()
        ).hexdigest()[:16]
        
        output_hash = hashlib.sha256(
            json.dumps(trace.output_data, sort_keys=True).encode()
        ).hexdigest()[:16]
        
        self.db.execute("""
            INSERT INTO execution_traces
            (task_id, operation, input_hash, output_hash, input_params,
             output_data, success, execution_time_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            trace.task_id,
            trace.operation,
            input_hash,
            output_hash,
            json.dumps(trace.input_params),
            json.dumps(trace.output_data),
            trace.success,
            trace.execution_time_ms
        ))
        
        self.db.commit()
    
    def learn_pattern(self, endpoint: str, pattern: APIPattern):
        """Register a learned pattern."""
        self.db.execute("""
            INSERT OR REPLACE INTO learned_patterns
            (endpoint, method, required_params, optional_params, auth_type,
             response_schema, request_headers, success_rate, call_count,
             last_used, documentation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            endpoint,
            pattern.method,
            json.dumps(pattern.required_params),
            json.dumps(pattern.optional_params),
            pattern.auth_type,
            json.dumps(pattern.response_schema),
            json.dumps(pattern.request_headers),
            pattern.success_rate,
            pattern.call_count,
            datetime.now().isoformat(),
            pattern.documentation
        ))
        
        self.db.commit()
        self.patterns[endpoint] = pattern
    
    def get_pattern(self, endpoint: str) -> APIPattern:
        """Retrieve a learned pattern."""
        if endpoint in self.patterns:
            return self.patterns[endpoint]
        
        # Try to load from DB if not in memory
        cursor = self.db.execute("""
            SELECT endpoint, method, required_params, optional_params,
                   auth_type, response_schema, request_headers, success_rate,
                   last_used, call_count, documentation
            FROM learned_patterns WHERE endpoint = ?
        """, (endpoint,))
        
        row = cursor.fetchone()
        if row:
            pattern = APIPattern(
                endpoint=row[0],
                method=row[1],
                required_params=json.loads(row[2]),
                optional_params=json.loads(row[3]),
                auth_type=row[4],
                response_schema=json.loads(row[5]),
                request_headers=json.loads(row[6]),
                success_rate=row[7],
                last_used=row[8],
                call_count=row[9],
                documentation=row[10]
            )
            self.patterns[endpoint] = pattern
            return pattern
        
        return None
    
    def generate_docs(self, endpoint: str, format: str = "markdown") -> str:
        """
        Auto-generate documentation for a learned pattern.
        Formats: "markdown", "json_schema", "curl_example", "python_code"
        """
        pattern = self.get_pattern(endpoint)
        if not pattern:
            return None
        
        if format == "markdown":
            return self._generate_markdown_docs(pattern)
        elif format == "json_schema":
            return self._generate_json_schema(pattern)
        elif format == "curl_example":
            return self._generate_curl_example(pattern)
        elif format == "python_code":
            return self._generate_python_code(pattern)
        
        return None
    
    def _generate_markdown_docs(self, pattern: APIPattern) -> str:
        """Generate markdown documentation."""
        doc = f"""# {pattern.endpoint}

## Summary
{pattern.documentation}

## Method
`{pattern.method}`

## Authentication
Type: `{pattern.auth_type}`

## Required Parameters
"""
        for param in pattern.required_params:
            doc += f"- `{param}`\n"
        
        doc += "\n## Optional Parameters\n"
        for param in pattern.optional_params:
            doc += f"- `{param}`\n"
        
        doc += f"\n## Request Headers\n"
        for key, value in pattern.request_headers.items():
            doc += f"- `{key}: {value}`\n"
        
        doc += f"\n## Response Schema\n```json\n{json.dumps(pattern.response_schema, indent=2)}\n```\n"
        
        doc += f"\n## Statistics\n"
        doc += f"- Success Rate: {pattern.success_rate * 100:.1f}%\n"
        doc += f"- Call Count: {pattern.call_count}\n"
        doc += f"- Last Used: {pattern.last_used}\n"
        
        return doc
    
    def _generate_json_schema(self, pattern: APIPattern) -> str:
        """Generate OpenAPI/JSON Schema."""
        schema = {
            "endpoint": pattern.endpoint,
            "method": pattern.method,
            "auth": pattern.auth_type,
            "parameters": {
                "required": pattern.required_params,
                "optional": pattern.optional_params
            },
            "headers": pattern.request_headers,
            "response": pattern.response_schema
        }
        return json.dumps(schema, indent=2)
    
    def _generate_curl_example(self, pattern: APIPattern) -> str:
        """Generate curl command example."""
        headers_str = " ".join([
            f"-H '{k}: {v}'" for k, v in pattern.request_headers.items()
        ])
        
        example = f"""curl -X {pattern.method} \\
  {headers_str} \\
  '{pattern.endpoint}'
"""
        return example
    
    def _generate_python_code(self, pattern: APIPattern) -> str:
        """Generate Python code example."""
        code = f"""
import requests

url = "{pattern.endpoint}"
headers = {json.dumps(pattern.request_headers, indent=2)}
params = {json.dumps({{p: f"<{p}>" for p in pattern.required_params}}, indent=2)}

response = requests.{pattern.method.lower()}(url, headers=headers, params=params)
data = response.json()
"""
        return code
    
    def similarity_search(self, task: str) -> List[str]:
        """
        Find similar previously-executed tasks.
        Returns list of endpoints/patterns that might be relevant.
        """
        # Simple substring matching; can be upgraded to semantic search
        matching_endpoints = []
        for endpoint in self.patterns:
            if task.lower() in endpoint.lower():
                matching_endpoints.append(endpoint)
        
        # Sort by call count (most used first)
        matching_endpoints.sort(
            key=lambda e: self.patterns[e].call_count,
            reverse=True
        )
        
        return matching_endpoints
    
    def generate_api_inventory(self) -> Dict[str, Any]:
        """
        Generate a complete inventory of all learned APIs.
        Use for reference or publication.
        """
        inventory = {
            "generated_at": datetime.now().isoformat(),
            "total_endpoints": len(self.patterns),
            "total_executions": self._get_total_executions(),
            "endpoints": []
        }
        
        for endpoint, pattern in sorted(
            self.patterns.items(),
            key=lambda x: x[1].call_count,
            reverse=True
        ):
            inventory["endpoints"].append({
                "endpoint": endpoint,
                "method": pattern.method,
                "auth": pattern.auth_type,
                "success_rate": pattern.success_rate,
                "calls": pattern.call_count,
                "documentation": pattern.documentation
            })
        
        return inventory
    
    def _get_total_executions(self) -> int:
        """Count total execution traces."""
        cursor = self.db.execute("SELECT COUNT(*) FROM execution_traces")
        return cursor.fetchone()[0]


if __name__ == "__main__":
    framework = SelfDocumentingFramework()
    
    # Example: Record a learned API
    pattern = APIPattern(
        endpoint="https://api.example.com/data",
        method="GET",
        required_params=["api_key"],
        optional_params=["limit", "offset"],
        auth_type="api_key",
        response_schema={"data": [], "total": 0},
        request_headers={"Authorization": "Bearer <token>"},
        success_rate=0.98,
        last_used=datetime.now(),
        call_count=150,
        documentation="Fetches data from Example API"
    )
    
    framework.learn_pattern("https://api.example.com/data", pattern)
    
    # Generate docs
    print(framework.generate_docs("https://api.example.com/data", "markdown"))
    
    # Show inventory
    inventory = framework.generate_api_inventory()
    print(json.dumps(inventory, indent=2))
