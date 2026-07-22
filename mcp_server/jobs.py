import asyncio
import json
import logging
import sqlite3
import uuid
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional, AsyncGenerator

logger = logging.getLogger(__name__)

# Config path for DB
if os.environ.get("MCP_TEST_CONFIG_DIR"):
    DB_DIR = Path(os.environ["MCP_TEST_CONFIG_DIR"])
elif os.name == 'nt':
    DB_DIR = Path.home() / ".mcp-kali"
else:
    DB_DIR = Path("/var/lib/mcp")

DB_FILE = DB_DIR / "jobs.db"

class JobManager:
    def __init__(self):
        self.listeners: Dict[str, list] = {}
        self._init_db()

    def _init_db(self):
        """Initialize persistent SQLite job store."""
        try:
            DB_DIR.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS jobs (
                        job_id TEXT PRIMARY KEY,
                        status TEXT,
                        server_id TEXT,
                        tool_name TEXT,
                        args TEXT,
                        result TEXT,
                        submitted_at TEXT,
                        completed_at TEXT
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize jobs DB: {e}")

    def submit_job(self, server_id: str, tool_name: str, args: Dict[str, Any], executor) -> str:
        """Submit a new background job with DB persistence."""
        job_id = str(uuid.uuid4())
        submitted_at = datetime.now(timezone.utc).isoformat()

        job_data = {
            "job_id": job_id,
            "status": "queued",
            "server_id": server_id,
            "tool_name": tool_name,
            "args": args,
            "result": None,
            "submitted_at": submitted_at,
            "completed_at": None
        }

        try:
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute(
                    "INSERT INTO jobs (job_id, status, server_id, tool_name, args, result, submitted_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (job_id, "queued", server_id, tool_name, json.dumps(args), None, submitted_at, None)
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Error persisting submitted job {job_id}: {e}")

        asyncio.create_task(self._run_job(job_id, server_id, tool_name, args, executor))
        logger.info(f"Submitted persistent async job {job_id} for tool {tool_name}")

        return job_id

    async def _run_job(self, job_id: str, server_id: str, tool_name: str, args: Dict[str, Any], executor):
        """Execute job in background and update DB status."""
        self._update_job_status(job_id, "running")
        self.notify_listeners(job_id, {"status": "running", "message": f"Job {job_id} started"})

        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, executor, server_id, args)

            result_dict = result.to_dict()
            result_dict["tool_name"] = tool_name
            result_dict["executed_at"] = datetime.now(timezone.utc).isoformat()
            result_dict["server_id"] = server_id

            completed_at = datetime.now(timezone.utc).isoformat()
            self._update_job_result(job_id, "completed", result_dict, completed_at)
            self.notify_listeners(job_id, {"status": "completed", "result": result_dict})

        except Exception as e:
            logger.error(f"Async job {job_id} failed: {e}")
            completed_at = datetime.now(timezone.utc).isoformat()
            err_result = {
                "rc": -1,
                "summary": f"Async execution failed: {str(e)}",
                "error": "EXECUTION_FAILED"
            }
            self._update_job_result(job_id, "failed", err_result, completed_at)
            self.notify_listeners(job_id, {"status": "failed", "result": err_result})

    def _update_job_status(self, job_id: str, status: str):
        try:
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute("UPDATE jobs SET status = ? WHERE job_id = ?", (status, job_id))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to update job status: {e}")

    def _update_job_result(self, job_id: str, status: str, result: Dict[str, Any], completed_at: str):
        try:
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute(
                    "UPDATE jobs SET status = ?, result = ?, completed_at = ? WHERE job_id = ?",
                    (status, json.dumps(result), completed_at, job_id)
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to update job result: {e}")

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve job status and results from persistent DB."""
        try:
            with sqlite3.connect(DB_FILE) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                
                return {
                    "job_id": row["job_id"],
                    "status": row["status"],
                    "server_id": row["server_id"],
                    "tool_name": row["tool_name"],
                    "args": json.loads(row["args"]) if row["args"] else {},
                    "result": json.loads(row["result"]) if row["result"] else None,
                    "submitted_at": row["submitted_at"],
                    "completed_at": row["completed_at"]
                }
        except Exception as e:
            logger.error(f"Error fetching job {job_id} from DB: {e}")
            return None

    def notify_listeners(self, job_id: str, data: Dict[str, Any]):
        """Helper to send SSE events to listeners."""
        if job_id in self.listeners:
            for q in self.listeners[job_id]:
                q.put_nowait(data)

    async def stream_job(self, job_id: str) -> AsyncGenerator[str, None]:
        """Server-Sent Events generator for a given job."""
        q = asyncio.Queue()
        if job_id not in self.listeners:
            self.listeners[job_id] = []
        self.listeners[job_id].append(q)

        # Yield current status
        current_job = self.get_job(job_id)
        if current_job:
            yield f"data: {json.dumps(current_job)}\n\n"

        try:
            while True:
                data = await q.get()
                yield f"data: {json.dumps(data)}\n\n"
                if data.get("status") in ["completed", "failed"]:
                    break
        finally:
            if job_id in self.listeners and q in self.listeners[job_id]:
                self.listeners[job_id].remove(q)

job_manager = JobManager()
