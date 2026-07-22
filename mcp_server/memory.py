"""
Memory module for MCP Kali Server.
Handles observation recording and lightweight fact persistence.
Enhanced with LLM conversation memory integration.
"""

import json
import logging
import sqlite3
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
import threading

logger = logging.getLogger(__name__)

# Memory storage configuration - handle both Windows and Linux
if os.name == 'nt':  # Windows
    MEMORY_BASE_DIR = Path.home() / ".mcp-kali" / "memory"
else:  # Linux/Unix
    MEMORY_BASE_DIR = Path("/var/lib/mcp/memory")
    
MEMORY_DB_FILE = MEMORY_BASE_DIR / "observations.db"

class MemoryManager:
    """Manages observation recording and memory persistence."""
    
    def __init__(self, db_path: Path = MEMORY_DB_FILE):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for memory storage."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS observations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        server_id TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        parsed_data TEXT,
                        created_at TEXT NOT NULL,
                        tags TEXT
                    )
                """)
                
                # Create indexes for efficient querying
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_server_id 
                    ON observations(server_id)
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_created_at 
                    ON observations(created_at DESC)
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_kind 
                    ON observations(kind)
                """)
                
                conn.commit()
                
            logger.info(f"Memory database initialized at {self.db_path}")
            
        except Exception as e:
            logger.error(f"Error initializing memory database: {e}")
    
    def record_observation(self, server_id: str, kind: str, summary: str, 
                         parsed_data: Optional[Dict[str, Any]] = None, 
                         tags: Optional[List[str]] = None) -> bool:
        """
        Record an observation in memory.
        
        Args:
            server_id: Server ID that made the observation
            kind: Type of observation (e.g., 'network_scan', 'web_scan')
            summary: Human-readable summary of the observation
            parsed_data: Optional structured data
            tags: Optional tags for categorization
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self._lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT INTO observations 
                        (server_id, kind, summary, parsed_data, created_at, tags)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        server_id,
                        kind,
                        summary,
                        json.dumps(parsed_data) if parsed_data else None,
                        datetime.now(timezone.utc).isoformat(),
                        json.dumps(tags) if tags else None
                    ))
                    
                    conn.commit()
                    
            logger.debug(f"Recorded observation: {kind} for server {server_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error recording observation: {e}")
            return False
    
    def search_memory(self, server_id: str, query: Optional[str] = None, 
                     kind: Optional[str] = None, limit: int = 50, 
                     offset: int = 0) -> Dict[str, Any]:
        """
        Search memory for observations.
        
        Args:
            server_id: Server ID to search for
            query: Optional text query to search in summaries
            kind: Optional observation kind filter
            limit: Maximum number of results
            offset: Offset for pagination
            
        Returns:
            Dictionary with search results and metadata
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row  # Enable column access by name
                
                # Build WHERE clause
                where_conditions = ["server_id = ?"]
                params = [server_id]
                
                if kind:
                    where_conditions.append("kind = ?")
                    params.append(kind)
                
                if query:
                    where_conditions.append("summary LIKE ?")
                    params.append(f"%{query}%")
                
                where_clause = " AND ".join(where_conditions)
                
                # Get total count
                count_query = f"""
                    SELECT COUNT(*) as total 
                    FROM observations 
                    WHERE {where_clause}
                """
                
                cursor = conn.execute(count_query, params)
                total = cursor.fetchone()["total"]
                
                # Get results with pagination
                results_query = f"""
                    SELECT id, kind, summary, parsed_data, created_at, tags
                    FROM observations 
                    WHERE {where_clause}
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """
                
                cursor = conn.execute(results_query, params + [limit, offset])
                rows = cursor.fetchall()
                
                # Convert to dictionaries
                observations = []
                for row in rows:
                    observation = {
                        "id": row["id"],
                        "kind": row["kind"],
                        "summary": row["summary"],
                        "created_at": row["created_at"],
                        "tags": json.loads(row["tags"]) if row["tags"] else []
                    }
                    
                    # Include parsed data if available
                    if row["parsed_data"]:
                        try:
                            observation["parsed_data"] = json.loads(row["parsed_data"])
                        except json.JSONDecodeError as e:
                            logger.error(f"Failed to decode parsed_data JSON: {e}")
                    
                    observations.append(observation)
                
                # Calculate next offset
                next_offset = offset + limit if offset + limit < total else None
                
                return {
                    "observations": observations,
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                    "nextOffset": next_offset,
                    "query": query,
                    "kind_filter": kind
                }
                
        except Exception as e:
            logger.error(f"Error searching memory: {e}")
            return {
                "observations": [],
                "total": 0,
                "error": str(e)
            }
    
    def get_recent_observations(self, server_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get most recent observations for a server.
        
        Args:
            server_id: Server ID
            limit: Maximum number of observations to return
            
        Returns:
            List of recent observations
        """
        result = self.search_memory(server_id, limit=limit)
        return result.get("observations", [])
    
    def get_observation_stats(self, server_id: str) -> Dict[str, Any]:
        """
        Get statistics about observations for a server.
        
        Args:
            server_id: Server ID
            
        Returns:
            Dictionary with observation statistics
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Total observations
                cursor = conn.execute(
                    "SELECT COUNT(*) as total FROM observations WHERE server_id = ?",
                    (server_id,)
                )
                total = cursor.fetchone()[0]
                
                # Observations by kind
                cursor = conn.execute("""
                    SELECT kind, COUNT(*) as count 
                    FROM observations 
                    WHERE server_id = ? 
                    GROUP BY kind 
                    ORDER BY count DESC
                """, (server_id,))
                
                by_kind = {row[0]: row[1] for row in cursor.fetchall()}
                
                # Recent activity (last 24 hours)
                recent_cutoff = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
                cursor = conn.execute("""
                    SELECT COUNT(*) as recent 
                    FROM observations 
                    WHERE server_id = ? AND created_at >= ?
                """, (server_id, recent_cutoff.isoformat()))
                
                recent = cursor.fetchone()[0]
                
                return {
                    "total_observations": total,
                    "by_kind": by_kind,
                    "recent_24h": recent,
                    "server_id": server_id
                }
                
        except Exception as e:
            logger.error(f"Error getting observation stats: {e}")
            return {"error": str(e)}
    
    def cleanup_old_observations(self, days_to_keep: int = 30) -> int:
        """
        Clean up old observations to prevent unlimited growth.
        
        Args:
            days_to_keep: Number of days of observations to keep
            
        Returns:
            Number of observations deleted
        """
        try:
            from datetime import timedelta
            
            cutoff_date = datetime.now(timezone.utc).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            cutoff_date = cutoff_date - timedelta(days=days_to_keep)
            
            with self._lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute("""
                        DELETE FROM observations 
                        WHERE created_at < ?
                    """, (cutoff_date.isoformat(),))
                    
                    deleted_count = cursor.rowcount
                    conn.commit()
                    
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old observations")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Error cleaning up old observations: {e}")
            return 0

# Global memory manager instance
memory_manager = MemoryManager()

def record_observation(server_id: str, kind: str, summary: str, 
                      parsed_data: Optional[Dict[str, Any]] = None,
                      tags: Optional[List[str]] = None) -> bool:
    """Record observation using global manager."""
    return memory_manager.record_observation(server_id, kind, summary, parsed_data, tags)

def search_memory(server_id: str, query: Optional[str] = None, 
                 kind: Optional[str] = None, limit: int = 50, 
                 offset: int = 0) -> Dict[str, Any]:
    """Search memory using global manager."""
    return memory_manager.search_memory(server_id, query, kind, limit, offset)

def get_recent_observations(server_id: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Get recent observations using global manager."""
    return memory_manager.get_recent_observations(server_id, limit)

def get_observation_stats(server_id: str) -> Dict[str, Any]:
    """Get observation statistics using global manager."""
    return memory_manager.get_observation_stats(server_id)

# Additional helper functions for memory integration

def extract_tags_from_findings(findings: List[Dict[str, Any]]) -> List[str]:
    """
    Extract relevant tags from tool findings for memory storage.
    
    Args:
        findings: Parsed findings from tool execution
        
    Returns:
        List of tags for categorization
    """
    tags = []
    
    try:
        for finding in findings:
            # Extract service names as tags
            if "ports" in finding:
                for port in finding["ports"]:
                    service = port.get("service", "").lower()
                    if service and service != "unknown":
                        tags.append(f"service:{service}")
                    
                    # Add port number for common services
                    port_num = port.get("port")
                    if port_num in [22, 23, 25, 53, 80, 110, 143, 443, 993, 995]:
                        tags.append(f"port:{port_num}")
            
            # Extract hostname tags
            hostname = finding.get("hostname")
            if hostname:
                tags.append(f"hostname:{hostname.lower()}")
        
        # Remove duplicates and limit to reasonable number
        tags = list(set(tags))[:10]
        
    except Exception as e:
        logger.error(f"Error extracting tags from findings: {e}")
    
    return tags

def create_memory_summary(tool_name: str, target: str, findings: List[Dict[str, Any]]) -> str:
    """
    Create a concise summary for memory storage.
    
    Args:
        tool_name: Name of the tool that was executed
        target: Target that was scanned
        findings: Results from the tool execution
        
    Returns:
        Concise summary string
    """
    try:
        if tool_name == "net.scan_basic":
            if not findings:
                return f"Network scan of {target} found no open ports"
            
            total_hosts = len(findings)
            total_ports = sum(len(host.get("ports", [])) for host in findings)
            
            # Extract unique services
            services = set()
            for host in findings:
                for port in host.get("ports", []):
                    service = port.get("service", "")
                    if service and service != "unknown":
                        services.add(service)
            
            summary = f"Network scan of {target}: {total_hosts} hosts, {total_ports} open ports"
            if services:
                service_list = sorted(list(services))[:3]
                summary += f" (services: {', '.join(service_list)})"
                if len(services) > 3:
                    summary += f" +{len(services) - 3} more"
            
            return summary
        
        # Generic summary for other tools
        return f"{tool_name} scan of {target}: {len(findings)} findings"
        
    except Exception as e:
        logger.error(f"Error creating memory summary: {e}")
        return f"{tool_name} scan of {target} completed"

def bridge_llm_memory_to_observations(server_id: str, thread_id: str, 
                                     role: str, content: str, meta: Dict[str, Any] = None):
    """Bridge LLM conversation memory to existing observation system."""
    try:
        manager = get_memory_manager()
        
        # Convert conversation turn to observation
        if role == "assistant" and meta and meta.get("tool_used"):
            # Assistant responses with tool usage become observations
            kind = f"chat_tool_response"
            summary = f"Assistant used {meta['tool_used']}: {content[:100]}..."
            parsed_data = {
                "thread_id": thread_id,
                "role": role,
                "tool_used": meta.get("tool_used"),
                "full_content": content
            }
            
            manager.record_observation(
                server_id=server_id,
                kind=kind,
                summary=summary,
                parsed=parsed_data
            )
            
        elif role == "user" and any(tool in content.lower() for tool in ["nmap", "scan", "exploit"]):
            # User requests for security tools become observations
            kind = "chat_security_request"
            summary = f"User requested: {content[:100]}..."
            parsed_data = {
                "thread_id": thread_id,
                "role": role,
                "request_type": "security_tool",
                "full_content": content
            }
            
            manager.record_observation(
                server_id=server_id,
                kind=kind,
                summary=summary,
                parsed=parsed_data
            )
            
    except Exception as e:
        logger.error(f"Error bridging LLM memory to observations: {e}")

def search_integrated_memory(server_id: str, query: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Search both LLM memory and observations for comprehensive results."""
    try:
        from .llm_db import get_llm_db
        
        results = []
        
        # Search LLM knowledge base
        llm_db = get_llm_db()
        knowledge_results = llm_db.search_knowledge(server_id, query, top_k=5)
        
        for result in knowledge_results["results"]:
            results.append({
                "type": "knowledge",
                "source": result["source"],
                "content": result["text"],
                "score": result["score"],
                "id": result["chunk_id"]
            })
        
        # Search existing observations
        manager = get_memory_manager()
        observations = manager.search_memory(server_id, query)
        
        for obs in observations[:5]:  # Limit to top 5
            results.append({
                "type": "observation",
                "source": obs.get("kind", "unknown"),
                "content": obs.get("summary", ""),
                "score": 0.5,  # Default score for observations
                "id": obs.get("id", "")
            })
        
        # Sort by score and return top results
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:limit]
        
    except Exception as e:
        logger.error(f"Error searching integrated memory: {e}")
        return []