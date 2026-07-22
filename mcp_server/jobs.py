"""
Asynchronous Job Management for MCP Server.
Tracks long-running tool executions and their status.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class JobManager:
    def __init__(self):
        self.jobs: Dict[str, Dict[str, Any]] = {}
        
    def submit_job(self, server_id: str, tool_name: str, args: Dict[str, Any], executor) -> str:
        """Submit a new background job."""
        job_id = str(uuid.uuid4())
        
        self.jobs[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "server_id": server_id,
            "tool_name": tool_name,
            "args": args,
            "result": None,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None
        }
        
        # Fire and forget the task
        asyncio.create_task(self._run_job(job_id, server_id, tool_name, args, executor))
        logger.info(f"Submitted async job {job_id} for tool {tool_name}")
        
        return job_id
        
    async def _run_job(self, job_id: str, server_id: str, tool_name: str, args: Dict[str, Any], executor):
        """Execute the job in the background."""
        self.jobs[job_id]["status"] = "running"
        
        try:
            # We run the synchronous executor in a thread pool to avoid blocking the ASGI event loop
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, executor, server_id, args)
            
            result_dict = result.to_dict()
            result_dict["tool_name"] = tool_name
            result_dict["executed_at"] = datetime.now(timezone.utc).isoformat()
            result_dict["server_id"] = server_id
            
            self.jobs[job_id]["status"] = "completed"
            self.jobs[job_id]["result"] = result_dict
            
        except Exception as e:
            logger.error(f"Async job {job_id} failed: {e}")
            self.jobs[job_id]["status"] = "failed"
            self.jobs[job_id]["result"] = {
                "rc": -1,
                "summary": f"Async execution failed: {str(e)}",
                "error": "EXECUTION_FAILED"
            }
            
        self.jobs[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        
    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve job status and results."""
        return self.jobs.get(job_id)

# Global singleton
job_manager = JobManager()
