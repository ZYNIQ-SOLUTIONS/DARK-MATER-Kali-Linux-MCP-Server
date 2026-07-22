"""
FastAPI application for MCP Kali Server.
Provides HTTP endpoints for enrollment, health checks, tools, and artifacts.
Enhanced with rate limiting, audit logging, and metrics collection.
"""

import os
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Depends, Query, status, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .auth import (
    require_api_key, enroll_server, EnrollmentRequest, EnrollmentResponse, 
    ServerCredentials, TokenRequest, TokenResponse, generate_jwt_token
)
from .tools import list_tools, call_tool, call_tool_async
from .jobs import job_manager
from .artifacts import list_artifacts, read_artifact
from .memory import search_memory, get_observation_stats
from .scope import get_scope_info
from .llm_db import get_llm_db
from .ngrok_manager import get_ngrok_info, get_ngrok_metrics
from .rate_limiter import apply_rate_limiting, get_client_identifier
from .audit import audit_logger, AuditEventType, AuditSeverity
from .metrics import metrics_collector

logger = logging.getLogger(__name__)

# Request/Response Models
class ToolCallRequest(BaseModel):
    """Request model for tool execution."""
    name: str
    arguments: Dict[str, Any]

class HealthResponse(BaseModel):
    """Health check response model."""
    ok: bool
    server_id: str
    caps: Dict[str, bool]
    time: str
    version: str = "2.0.0"

class ErrorResponse(BaseModel):
    """Error response model."""
    error: str
    detail: Optional[str] = None

# LLM Configuration Models
class LLMConfigRequest(BaseModel):
    """Request model for LLM configuration updates."""
    system_prompt: Optional[str] = None
    guardrails: Optional[Dict[str, Any]] = None
    runtime_hints: Optional[Dict[str, Any]] = None
    tools_allowed: Optional[list] = None

class KnowledgeDocRequest(BaseModel):
    """Request model for knowledge document creation."""
    title: str
    source: Optional[str] = None
    tags: Optional[list] = None

class KnowledgeChunksRequest(BaseModel):
    """Request model for adding knowledge chunks."""
    chunks: list

class MemoryAppendRequest(BaseModel):
    """Request model for appending to memory."""
    thread_id: str
    role: str
    content: str
    meta: Optional[Dict[str, Any]] = None

class MemorySummarizeRequest(BaseModel):
    """Request model for memory summarization."""
    thread_id: str
    summary: str

# Create FastAPI application
app = FastAPI(
    title="MCP Kali Server",
    description="Production-ready security testing server with enrollment and artifact storage",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware for dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware for metrics and audit logging
@app.middleware("http")
async def metrics_and_audit_middleware(request: Request, call_next):
    """Middleware for metrics collection and audit logging."""
    start_time = time.time()
    client_id = get_client_identifier(request)
    client_ip = request.client.host if request.client else "unknown"
    
    # Apply rate limiting (before processing request)
    try:
        await apply_rate_limiting(request)
    except HTTPException as e:
        # Log rate limit violation
        await audit_logger.log_security_violation(
            user_id=client_id,
            violation_type="rate_limit_exceeded",
            target=request.url.path,
            client_ip=client_ip,
            details={"status_code": e.status_code, "detail": e.detail}
        )
        return JSONResponse(status_code=e.status_code, content={"detail": e.detail})
    
    # Process request
    response = await call_next(request)
    
    # Calculate metrics
    duration = time.time() - start_time
    
    # Record metrics
    metrics_collector.increment_request_count(
        request.url.path, request.method, response.status_code
    )
    metrics_collector.record_response_time(
        request.url.path, request.method, duration
    )
    
    # Log API access (for non-health endpoints to reduce noise)
    if not request.url.path.startswith("/health"):
        await audit_logger.log_api_access(
            user_id=client_id,
            endpoint=request.url.path,
            method=request.method,
            status_code=response.status_code,
            client_ip=client_ip,
            duration=duration
        )
    
    return response

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc):
    """Handle unexpected exceptions gracefully."""
    logger.error(f"Unhandled exception in {request.url}: {exc}", exc_info=True)
    
    # Log security event for unexpected errors
    client_id = get_client_identifier(request)
    client_ip = request.client.host if request.client else "unknown"
    
    await audit_logger.log_security_violation(
        user_id=client_id,
        violation_type="unhandled_exception",
        target=request.url.path,
        client_ip=client_ip,
        details={"exception": str(exc), "type": type(exc).__name__}
    )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred"
        }
    )

# Mount static files for schemas
schema_dir = Path(__file__).parent / "schemas"
if schema_dir.exists():
    app.mount("/schemas", StaticFiles(directory=str(schema_dir)), name="schemas")

# Enrollment endpoint (public - no authentication required)
@app.post("/enroll", response_model=EnrollmentResponse)
async def enroll_endpoint(request: EnrollmentRequest):
    """
    Enroll a new server and generate API credentials.
    
    This endpoint is public and uses the enrollment token for authentication.
    """
    try:
        logger.info(f"Enrollment request from server: {request.id}")
        response = enroll_server(request)
        logger.info(f"Successfully enrolled server: {response.server_id}")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Enrollment error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Enrollment failed due to server error"
        )

# JWT Token endpoint
@app.post("/auth/token", response_model=TokenResponse)
async def create_access_token(request: TokenRequest):
    """Generate JWT token for dashboard authentication using API key."""
    try:
        if not request.api_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="API key is required"
            )
        
        # Validate API key and get server credentials
        from .auth import load_api_credentials
        credentials = load_api_credentials()
        
        # Find server by API key
        server_id = None
        for cred in credentials:
            if cred.get("api_key") == request.api_key:
                server_id = cred.get("server_id")
                break
        
        if not server_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )
        
        # Generate JWT token
        token_data = generate_jwt_token(server_id)
        
        logger.info(f"Generated JWT token for server: {server_id}")
        return TokenResponse(**token_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token generation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token generation failed"
        )

# Health check endpoint (requires authentication)
@app.get("/health", response_model=HealthResponse)
async def health_check(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Health check endpoint with server capabilities.
    
    Returns server status and available capabilities.
    """
    try:
        return HealthResponse(
            ok=True,
            server_id=server_creds.server_id,
            caps={
                "tools": True,
                "artifacts": True,
                "memory": True,
                "scope_validation": True,
                "schema_validation": True
            },
            time=datetime.now(timezone.utc).isoformat()
        )
        
    except Exception as e:
        logger.error(f"Health check error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Health check failed"
        )

# Tools endpoints
@app.get("/tools/list")
async def tools_list_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Get list of available tools with metadata.
    
    Returns tool names, descriptions, and schema references.
    """
    try:
        tools = list_tools()
        return {"tools": tools}
        
    except Exception as e:
        logger.error(f"Tools list error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve tools list"
        )

@app.post("/tools/call")
async def tools_call_endpoint(
    request: ToolCallRequest,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """
    Execute a tool with the provided arguments.
    
    Validates arguments against schema and checks scope/destructiveness.
    """
    try:
        logger.info(f"Tool call request: {request.name} from server {server_creds.server_id}")
        
        result = call_tool(server_creds.server_id, request.name, request.arguments)
        
        # Log the result (without sensitive data)
        if result.get("rc") == 0:
            logger.info(f"Tool {request.name} executed successfully")
        else:
            logger.warning(f"Tool {request.name} failed: {result.get('summary', 'Unknown error')}")
        
        return result
        
    except Exception as e:
        logger.error(f"Tool call error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Tool execution failed due to server error"
        )

@app.post("/tools/jobs")
async def submit_tool_job(
    request: ToolCallRequest,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """
    Submit a tool for asynchronous background execution.
    
    Returns a job_id immediately, which can be polled for status.
    """
    try:
        logger.info(f"Async tool job request: {request.name} from server {server_creds.server_id}")
        
        result = call_tool_async(server_creds.server_id, request.name, request.arguments)
        
        if result.get("status") == "queued":
            return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=result)
        else:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=result)
            
    except Exception as e:
        logger.error(f"Async tool submission error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Tool submission failed due to server error"
        )

@app.get("/tools/jobs/{job_id}")
async def get_job_status(
    job_id: str,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """
    Poll the status of an asynchronous background job.
    """
    try:
        job = job_manager.get_job(job_id)
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job not found: {job_id}"
            )
            
        # Optional: ensure the server requesting it owns the job
        if job.get("server_id") != server_creds.server_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view this job"
            )
            
        return job
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Job status retrieval error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Job status retrieval failed"
        )

# AI Analysis endpoints
@app.post("/tools/jobs/{job_id}/analyze")
async def analyze_job(job_id: str, server_creds: ServerCredentials = Depends(require_api_key)):
    """Analyze a completed job using AI."""
    try:
        from mcp_tools import get_tool_manager
        manager = get_tool_manager()
        
        # Get AI configuration from environment or use defaults
        ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        model = os.getenv("OLLAMA_MODEL", "llama2")
        
        result = await manager.analyze_job(job_id, ollama_url, model)
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error analyzing job {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Analysis failed")

@app.get("/tools/jobs/{job_id}/suggestions")
async def get_next_tool_suggestions(job_id: str, server_creds: ServerCredentials = Depends(require_api_key)):
    """Get AI suggestions for next tools to run."""
    try:
        from mcp_tools import get_tool_manager
        manager = get_tool_manager()
        
        # Get AI configuration from environment or use defaults
        ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        model = os.getenv("OLLAMA_MODEL", "llama2")
        
        suggestions = await manager.suggest_next_tools(job_id, ollama_url, model)
        return {"suggestions": suggestions}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting suggestions for job {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get suggestions")

@app.post("/tools/analysis/executive-summary")
async def generate_executive_summary(
    request: Dict[str, Any] = None,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Generate an executive summary of multiple jobs."""
    try:
        from mcp_tools import get_tool_manager
        manager = get_tool_manager()
        
        # Get AI configuration from environment or use defaults
        ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        model = os.getenv("OLLAMA_MODEL", "llama2")
        
        job_ids = None
        if request and "job_ids" in request:
            job_ids = request["job_ids"]
        
        result = await manager.generate_executive_summary(job_ids, ollama_url, model)
        return result
    except Exception as e:
        logger.error(f"Error generating executive summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate summary")

# LLM Configuration endpoints
@app.get("/llm/config")
async def get_llm_config(server_creds: ServerCredentials = Depends(require_api_key)):
    """Get LLM configuration for this server."""
    try:
        db = get_llm_db()
        config = db.get_llm_config(server_creds.server_id)
        
        if not config:
            # Return default configuration
            default_config = {
                "version": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "server_id": server_creds.server_id,
                "system_prompt": f"You are the MCP Server Assistant for {server_creds.server_id}. Use only provided memory and tools. Be concise and security-focused.",
                "guardrails": {
                    "disallowed": ["secrets", "credentials", "passwords"],
                    "style": "concise",
                    "max_tokens_hint": 200
                },
                "runtime_hints": {
                    "preferred_model": "phi3:mini",
                    "num_ctx": 768,
                    "temperature": 0.2,
                    "num_gpu": 0,
                    "keep_alive": 0
                },
                "tools_allowed": [],
                "etag": "default"
            }
            # Save default config
            config = db.set_llm_config(server_creds.server_id, default_config)
        
        return config
    except Exception as e:
        logger.error(f"Error getting LLM config: {e}")
        raise HTTPException(status_code=500, detail="Failed to get LLM configuration")

@app.put("/llm/config")
async def update_llm_config(
    request: LLMConfigRequest,
    if_match: Optional[str] = None,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Update LLM configuration with optimistic concurrency control."""
    try:
        db = get_llm_db()
        
        # Check ETag for optimistic concurrency
        if if_match:
            current_etag = db.get_config_etag(server_creds.server_id)
            if current_etag and current_etag != if_match:
                raise HTTPException(status_code=409, detail="Configuration was modified by another client")
        
        # Get current config to merge with updates
        current_config = db.get_llm_config(server_creds.server_id) or {}
        
        # Build updated config
        updated_config = {}
        if request.system_prompt is not None:
            updated_config["system_prompt"] = request.system_prompt
        else:
            updated_config["system_prompt"] = current_config.get("system_prompt", "")
            
        if request.guardrails is not None:
            updated_config["guardrails"] = request.guardrails
        else:
            updated_config["guardrails"] = current_config.get("guardrails", {})
            
        if request.runtime_hints is not None:
            updated_config["runtime_hints"] = request.runtime_hints
        else:
            updated_config["runtime_hints"] = current_config.get("runtime_hints", {})
            
        if request.tools_allowed is not None:
            updated_config["tools_allowed"] = request.tools_allowed
        else:
            updated_config["tools_allowed"] = current_config.get("tools_allowed", [])
        
        # Validate tools_allowed against available tools
        if updated_config["tools_allowed"]:
            available_tools = [tool["name"] for tool in list_tools()]
            invalid_tools = [t for t in updated_config["tools_allowed"] if t not in available_tools]
            if invalid_tools:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Invalid tools specified: {invalid_tools}"
                )
        
        # Save configuration
        config = db.set_llm_config(server_creds.server_id, updated_config)
        return config
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating LLM config: {e}")
        raise HTTPException(status_code=500, detail="Failed to update LLM configuration")

@app.get("/llm/config/etag")
async def get_config_etag(server_creds: ServerCredentials = Depends(require_api_key)):
    """Get ETag for configuration caching."""
    try:
        db = get_llm_db()
        etag = db.get_config_etag(server_creds.server_id)
        return {"etag": etag or "none"}
    except Exception as e:
        logger.error(f"Error getting config ETag: {e}")
        raise HTTPException(status_code=500, detail="Failed to get ETag")

# Knowledge Management endpoints
@app.post("/llm/knowledge/docs")
async def create_knowledge_doc(
    request: KnowledgeDocRequest,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Create a new knowledge document."""
    try:
        db = get_llm_db()
        doc_id = db.create_knowledge_doc(
            server_creds.server_id,
            request.title,
            request.source,
            request.tags
        )
        return {"doc_id": doc_id, "title": request.title}
    except Exception as e:
        logger.error(f"Error creating knowledge doc: {e}")
        raise HTTPException(status_code=500, detail="Failed to create knowledge document")

@app.put("/llm/knowledge/docs/{doc_id}")
async def update_knowledge_doc(
    doc_id: str,
    request: KnowledgeDocRequest,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Update knowledge document metadata."""
    try:
        db = get_llm_db()
        success = db.update_knowledge_doc(
            doc_id,
            request.title,
            request.source,
            request.tags
        )
        if not success:
            raise HTTPException(status_code=404, detail="Document not found")
        return {"doc_id": doc_id, "updated": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating knowledge doc: {e}")
        raise HTTPException(status_code=500, detail="Failed to update knowledge document")

@app.delete("/llm/knowledge/docs/{doc_id}")
async def delete_knowledge_doc(
    doc_id: str,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Delete a knowledge document and its chunks."""
    try:
        db = get_llm_db()
        success = db.delete_knowledge_doc(doc_id)
        if not success:
            raise HTTPException(status_code=404, detail="Document not found")
        return {"doc_id": doc_id, "deleted": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting knowledge doc: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete knowledge document")

@app.post("/llm/knowledge/docs/{doc_id}/chunks")
async def add_knowledge_chunks(
    doc_id: str,
    request: KnowledgeChunksRequest,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Add text chunks to a knowledge document."""
    try:
        db = get_llm_db()
        chunk_ids = db.add_knowledge_chunks(doc_id, request.chunks)
        return {"doc_id": doc_id, "chunk_ids": chunk_ids, "count": len(chunk_ids)}
    except Exception as e:
        logger.error(f"Error adding knowledge chunks: {e}")
        raise HTTPException(status_code=500, detail="Failed to add knowledge chunks")

@app.get("/llm/knowledge/search")
async def search_knowledge(
    q: str = Query(..., description="Search query"),
    top_k: int = Query(4, ge=1, le=20, description="Number of results to return"),
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Search knowledge base using FTS5."""
    try:
        db = get_llm_db()
        results = db.search_knowledge(server_creds.server_id, q, top_k)
        return results
    except Exception as e:
        logger.error(f"Error searching knowledge: {e}")
        raise HTTPException(status_code=500, detail="Failed to search knowledge base")

@app.post("/llm/knowledge/reindex")
async def reindex_knowledge(server_creds: ServerCredentials = Depends(require_api_key)):
    """Rebuild knowledge search index."""
    try:
        db = get_llm_db()
        count = db.reindex_knowledge(server_creds.server_id)
        return {"reindexed": count, "server_id": server_creds.server_id}
    except Exception as e:
        logger.error(f"Error reindexing knowledge: {e}")
        raise HTTPException(status_code=500, detail="Failed to reindex knowledge base")

# Memory Management endpoints
@app.get("/memory/retrieve")
async def retrieve_memory(
    thread_id: str = Query(..., description="Thread ID"),
    q: Optional[str] = Query(None, description="Optional query for semantic snippets"),
    limit: int = Query(8, ge=1, le=50, description="Number of turns to retrieve"),
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Retrieve conversation memory for a thread."""
    try:
        db = get_llm_db()
        result = db.retrieve_memory(server_creds.server_id, thread_id, q, limit)
        return result
    except Exception as e:
        logger.error(f"Error retrieving memory: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve memory")

@app.post("/memory/append")
async def append_memory(
    request: MemoryAppendRequest,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Append a conversation turn to memory."""
    try:
        # Validate role
        if request.role not in ["user", "assistant", "system"]:
            raise HTTPException(status_code=400, detail="Invalid role. Must be user, assistant, or system")
        
        db = get_llm_db()
        memory_id = db.append_memory(
            server_creds.server_id,
            request.thread_id,
            request.role,
            request.content,
            request.meta
        )
        
        # Bridge to existing observation system
        from .memory import bridge_llm_memory_to_observations
        bridge_llm_memory_to_observations(
            server_creds.server_id,
            request.thread_id,
            request.role,
            request.content,
            request.meta
        )
        
        return {"memory_id": memory_id, "thread_id": request.thread_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error appending memory: {e}")
        raise HTTPException(status_code=500, detail="Failed to append memory")

@app.post("/memory/summarize")
async def summarize_memory(
    request: MemorySummarizeRequest,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Create a memory summary and optionally clean old turns."""
    try:
        db = get_llm_db()
        summary_id = db.summarize_memory(
            server_creds.server_id,
            request.thread_id,
            request.summary
        )
        return {"summary_id": summary_id, "thread_id": request.thread_id}
    except Exception as e:
        logger.error(f"Error summarizing memory: {e}")
        raise HTTPException(status_code=500, detail="Failed to summarize memory")

# Live Context endpoint
@app.get("/llm/context")
async def get_live_context(server_creds: ServerCredentials = Depends(require_api_key)):
    """Get dynamic server context for better LLM responses."""
    try:
        db = get_llm_db()
        
        # Get basic server status
        import psutil
        import platform
        from datetime import timedelta
        
        # Calculate uptime
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        uptime = str(timedelta(seconds=int(uptime_seconds)))
        
        # Get disk usage
        disk = psutil.disk_usage('/')
        disk_usage = f"{disk.percent:.1f}% ({disk.free // (1024**3)} GB free)"
        
        # Check key services (mock for now)
        services = [
            {"name": "ssh", "state": "active"},
            {"name": "nginx", "state": "inactive"},
            {"name": "postgres", "state": "active"}
        ]
        
        # Check for alerts (placeholder)
        alerts = []
        if disk.percent > 90:
            alerts.append({"type": "warning", "message": "Disk usage high"})
        
        # Update and get server status
        status_data = {
            "uptime": uptime,
            "disk_usage": disk_usage,
            "services": services,
            "alerts": alerts,
            "last_scan": "2025-10-05T10:30:00Z"  # Placeholder
        }
        
        db.update_server_status(server_creds.server_id, status_data)
        
        return {
            "server_id": server_creds.server_id,
            "uptime": uptime,
            "alerts": alerts,
            "services": services,
            "disk_usage": disk_usage,
            "last_scan": status_data["last_scan"]
        }
        
    except Exception as e:
        logger.error(f"Error getting live context: {e}")
        raise HTTPException(status_code=500, detail="Failed to get live context")

# Artifacts endpoints
@app.get("/artifacts/list")
async def artifacts_list_endpoint(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """
    List artifacts for the authenticated server.
    
    Supports pagination with limit and offset parameters.
    """
    try:
        result = list_artifacts(server_creds.server_id, limit, offset)
        return result
        
    except Exception as e:
        logger.error(f"Artifacts list error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve artifacts list"
        )

@app.get("/artifacts/read")
async def artifacts_read_endpoint(
    uri: str = Query(..., description="Artifact URI to read"),
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """
    Read artifact content by URI.
    
    Validates that the artifact belongs to the authenticated server.
    """
    try:
        # Validate that the URI belongs to this server
        if not uri.startswith(f"artifact://{server_creds.server_id}/"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: artifact does not belong to this server"
            )
        
        artifact = read_artifact(uri)
        if not artifact:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Artifact not found"
            )
        
        # Return the artifact metadata and content wrapped in a JSON response
        return artifact
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Artifact read error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to read artifact"
        )

# Memory endpoints
@app.get("/memory/search")
async def memory_search_endpoint(
    query: Optional[str] = Query(None, description="Search query"),
    kind: Optional[str] = Query(None, description="Observation kind filter"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """
    Search memory observations for the authenticated server.
    
    Supports text search and filtering by observation kind.
    """
    try:
        result = search_memory(server_creds.server_id, query, kind, limit, offset)
        return result
        
    except Exception as e:
        logger.error(f"Memory search error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to search memory"
        )

@app.get("/memory/stats")
async def memory_stats_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Get memory statistics for the authenticated server.
    
    Returns counts and breakdowns of stored observations.
    """
    try:
        stats = get_observation_stats(server_creds.server_id)
        return stats
        
    except Exception as e:
        logger.error(f"Memory stats error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve memory statistics"
        )

# Configuration endpoints
@app.get("/config/scope")
async def scope_config_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Get current scope configuration.
    
    Returns allowed CIDRs and destructive operation settings.
    """
    try:
        scope_info = get_scope_info()
        return scope_info
        
    except Exception as e:
        logger.error(f"Scope config error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scope configuration"
        )

# Ngrok endpoints
@app.get("/ngrok/info")
async def ngrok_info_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Get ngrok tunnel information.
    
    Returns current tunnel status and public URL.
    """
    try:
        ngrok_info = get_ngrok_info()
        return ngrok_info
        
    except Exception as e:
        logger.error(f"Ngrok info error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve ngrok information"
        )

@app.get("/ngrok/metrics")
async def ngrok_metrics_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Get ngrok tunnel metrics.
    
    Returns connection and traffic statistics if available.
    """
    try:
        metrics = get_ngrok_metrics()
        if metrics:
            return metrics
        else:
            return {"message": "Metrics not available"}
        
    except Exception as e:
        logger.error(f"Ngrok metrics error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve ngrok metrics"
        )

# Enhanced API endpoints for monitoring and security

@app.get("/api/v2/metrics")
async def get_metrics_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Get comprehensive server metrics.
    
    Returns request metrics, tool metrics, and system metrics.
    """
    try:
        metrics = metrics_collector.get_all_metrics()
        return metrics
        
    except Exception as e:
        logger.error(f"Metrics endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve metrics"
        )

@app.get("/metrics", response_class=PlainTextResponse)
async def get_prometheus_metrics_endpoint():
    """
    Get Prometheus-compatible server metrics.
    
    This endpoint is designed to be scraped by Prometheus or similar monitoring tools.
    It intentionally does NOT require an API key to allow local scrapers to work easily,
    but in production, it should be restricted via network policies.
    """
    try:
        content = metrics_collector.get_prometheus_metrics()
        return PlainTextResponse(content=content)
    except Exception as e:
        logger.error(f"Prometheus metrics endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate Prometheus metrics"
        )

@app.get("/api/v2/audit/events")
async def get_audit_events(
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, description="Maximum number of results"),
    offset: int = Query(0, description="Offset for pagination"),
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """
    Get audit events with optional filtering.
    
    Provides comprehensive audit trail for compliance and security monitoring.
    """
    try:
        # Convert string enums if provided
        event_type_enum = None
        if event_type:
            try:
                event_type_enum = AuditEventType(event_type)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid event_type: {event_type}"
                )
        
        severity_enum = None
        if severity:
            try:
                severity_enum = AuditSeverity(severity)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid severity: {severity}"
                )
        
        events = await audit_logger.search_events(
            event_type=event_type_enum,
            user_id=user_id,
            severity=severity_enum,
            limit=limit,
            offset=offset
        )
        
        return {
            "events": events,
            "limit": limit,
            "offset": offset,
            "nextOffset": offset + limit if len(events) == limit else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Audit events endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve audit events"
        )

@app.get("/api/v2/audit/stats")
async def get_audit_stats(
    days: int = Query(7, description="Number of days to include in statistics"),
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """
    Get audit event statistics.
    
    Returns summary statistics for audit events over the specified period.
    """
    try:
        stats = await audit_logger.get_event_statistics(days=days)
        return stats
        
    except Exception as e:
        logger.error(f"Audit stats endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve audit statistics"
        )

@app.get("/health/detailed")
async def detailed_health_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Get detailed health information including system metrics.
    
    Provides comprehensive health status for monitoring dashboards.
    """
    try:
        # Basic health info
        basic_health = {
            "ok": True,
            "server_id": server_creds.server_id,
            "time": datetime.now(timezone.utc).isoformat(),
            "version": "2.0.0"
        }
        
        # Add system metrics
        system_metrics = metrics_collector.get_system_metrics()
        
        # Add service status checks
        service_checks = {
            "database": True,  # Could add actual DB connectivity check
            "filesystem": True,  # Could add disk space check
            "tools_available": len(list_tools()) > 0
        }
        
        # Add current stats
        request_metrics = metrics_collector.get_request_metrics()
        tool_metrics = metrics_collector.get_tool_metrics()
        
        return {
            **basic_health,
            "checks": service_checks,
            "system": system_metrics,
            "performance": {
                "uptime_seconds": request_metrics.get("uptime_hours", 0) * 3600,
                "total_requests": request_metrics.get("total_requests", 0),
                "error_rate": request_metrics.get("error_rate", 0),
                "active_connections": request_metrics.get("active_connections", 0)
            },
            "tools": {
                "total_executions": tool_metrics.get("total_tool_executions", 0),
                "available_tools": len(list_tools())
            }
        }
        
    except Exception as e:
            logger.error(f"Detailed health endpoint error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve detailed health information"
            )

# Dashboard Integration Endpoints

@app.post("/api/v2/dashboard/auth")
async def dashboard_auth_endpoint(auth_request: "DashboardAuthRequest"):
    """
    Authenticate DARK MATTER MCP Client dashboard.
    
    Provides specialized authentication for the dashboard with signature verification.
    """
    try:
        from .dashboard import dashboard_manager, DashboardAuthRequest
        
        # Validate request
        dashboard_auth_req = DashboardAuthRequest(**auth_request.dict())
        
        # Authenticate dashboard
        connection_info = dashboard_manager.authenticate_dashboard(dashboard_auth_req)
        
        if not connection_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Dashboard authentication failed"
            )
        
        # Log successful dashboard authentication
        client_ip = "dashboard"  # Dashboard connections
        await audit_logger.log_authentication(
            user_id=f"dashboard_{connection_info.dashboard_id}",
            success=True,
            client_ip=client_ip,
            details={"connection_type": "dashboard", "permissions": connection_info.permissions}
        )
        
        return {
            "connection_token": connection_info.connection_token,
            "expires_at": connection_info.expires_at.isoformat(),
            "permissions": connection_info.permissions,
            "server_capabilities": dashboard_manager.get_dashboard_capabilities().model_dump()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Dashboard auth endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Dashboard authentication failed"
        )

@app.get("/api/v2/dashboard/capabilities")
async def dashboard_capabilities_endpoint():
    """
    Get dashboard capabilities and available features.
    
    Public endpoint that provides information about server capabilities.
    """
    try:
        from .dashboard import dashboard_manager
        
        capabilities = dashboard_manager.get_dashboard_capabilities()
        return capabilities.model_dump()
        
    except Exception as e:
        logger.error(f"Dashboard capabilities endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard capabilities"
        )

@app.get("/api/v2/dashboard/data")
async def dashboard_data_endpoint(
    dashboard_id: str = Query(..., description="Dashboard ID"),
    connection_token: str = Query(..., description="Dashboard connection token")
):
    """
    Get aggregated data for dashboard display.
    
    Provides comprehensive data optimized for dashboard consumption.
    """
    try:
        from .dashboard import dashboard_manager
        
        # Verify dashboard authentication
        if not dashboard_manager.verify_connection_token(dashboard_id, connection_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid dashboard credentials"
            )
        
        # Get dashboard-specific data
        data = dashboard_manager.get_dashboard_specific_data(dashboard_id)
        
        return data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Dashboard data endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,  
            detail="Failed to retrieve dashboard data"
        )

@app.get("/api/v2/license/status")
async def license_status_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Get current license status and information.
    
    Returns licensing information for compliance and monitoring.
    """
    try:
        from .licensing import get_license_status
        
        status_info = get_license_status()
        return status_info
        
    except Exception as e:
        logger.error(f"License status endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve license status"
        )# Server information endpoint
@app.get("/info")
async def server_info_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """
    Get server information and statistics.
    
    Returns comprehensive server status and usage statistics.
    """
    try:
        # Get memory stats
        memory_stats = get_observation_stats(server_creds.server_id)
        
        # Get artifacts count
        artifacts_info = list_artifacts(server_creds.server_id, limit=1)
        
        # Get scope info
        scope_info = get_scope_info()
        
        # Get ngrok info
        ngrok_info = get_ngrok_info()
        
        return {
            "server_id": server_creds.server_id,
            "label": server_creds.label,
            "enrolled_at": server_creds.created.isoformat(),
            "memory_stats": memory_stats,
            "artifacts_count": artifacts_info.get("total", 0),
            "scope_config": scope_info,
            "available_tools": len(list_tools()),
            "ngrok_tunnel": ngrok_info,
            "server_time": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Server info error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve server information"
        )

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with basic server information."""
    return {
        "name": "MCP Kali Server",
        "version": "2.0.0",
        "description": "Production-ready security testing server",
        "endpoints": {
            "enrollment": "/enroll",
            "health": "/health",
            "tools": "/tools/list",
            "artifacts": "/artifacts/list",
            "memory": "/memory/search",
            "documentation": "/docs"
        }
    }

# Additional utility endpoints for dashboard integration
@app.get("/status")
async def status_endpoint():
    """
    Public status endpoint for basic health monitoring.
    
    Does not require authentication - suitable for load balancers.
    """
    try:
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "2.0.0"
        }
    except Exception as e:
        logger.error(f"Status check error: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"status": "unhealthy", "error": str(e)}
        )

# Startup event handler
@app.on_event("startup")
async def startup_event():
    """Initialize server on startup."""
    logger.info("MCP Kali Server starting up...")
    
    # Ensure scope configuration exists
    try:
        from .scope import ensure_scope_config
        ensure_scope_config()
    except Exception as e:
        logger.error(f"Error initializing scope config: {e}")
    
    logger.info("MCP Kali Server startup complete")

# Webhook Management Endpoints

@app.get("/api/v2/webhooks")
async def list_webhooks_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """List all configured webhooks."""
    try:
        from .webhooks import webhook_manager
        
        webhooks = webhook_manager.list_webhooks()
        return {"webhooks": webhooks}
        
    except Exception as e:
        logger.error(f"List webhooks endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve webhooks"
        )

@app.post("/api/v2/webhooks")
async def add_webhook_endpoint(
    webhook_data: Dict[str, Any],
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Add a new webhook configuration."""
    try:
        from .webhooks import webhook_manager, WebhookConfig
        
        webhook = WebhookConfig(**webhook_data)
        success = webhook_manager.add_webhook(webhook)
        
        if success:
            return {"message": "Webhook added successfully", "webhook_id": webhook.id}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to add webhook"
            )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid webhook configuration: {e}"
        )
    except Exception as e:
        logger.error(f"Add webhook endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add webhook"
        )

# Report Generation Endpoints

@app.post("/api/v2/reports/generate")
async def generate_report_endpoint(
    report_request: Dict[str, Any],
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Generate a comprehensive security report."""
    try:
        from .reports import report_generator, ReportConfig
        
        # Extract configuration
        config = ReportConfig(**report_request.get("config", {}))
        scan_ids = report_request.get("scan_ids", [])
        
        # Generate report
        result = await report_generator.generate_report(
            server_id=server_creds.server_id,
            config=config,
            scan_ids=scan_ids
        )
        
        return result
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid report configuration: {e}"
        )
    except Exception as e:
        logger.error(f"Generate report endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate report"
        )

@app.get("/api/v2/tools/templates")
async def get_tool_templates_endpoint(server_creds: ServerCredentials = Depends(require_api_key)):
    """Get pre-configured tool execution templates."""
    templates = {
        "quick_scan": {
            "name": "Quick Security Scan",
            "tools": [{"name": "net.scan_basic", "params": {"fast": True}}]
        },
        "comprehensive_scan": {
            "name": "Comprehensive Assessment", 
            "tools": [
                {"name": "net.scan_basic", "params": {"fast": False}},
                {"name": "web.nikto", "params": {"timeout": 300}},
                {"name": "ssl.sslyze", "params": {"check_vulnerabilities": True}}
            ]
        },
        "web_assessment": {
            "name": "Web Security Test",
            "tools": [
                {"name": "web.nikto", "params": {"timeout": 600}},
                {"name": "web.dirb", "params": {"wordlist": "big"}}
            ]
        }
    }
    
    return {"templates": templates}

# Tool Management Endpoints (New Modular System)
@app.get("/api/tools")
async def get_available_tools(
    category: Optional[str] = None,
    available_only: bool = True,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Get list of available pentesting tools from the modular registry."""
    try:
        from mcp_tools.manager import get_tool_manager
        
        tool_manager = get_tool_manager()
        tools = tool_manager.list_tools(category=category, available_only=available_only)
        categories = tool_manager.get_categories()
        
        return {
            "tools": tools,
            "categories": categories,
            "total_tools": len(tools),
            "force_mode": tool_manager.force_mode
        }
        
    except Exception as e:
        logger.error(f"Get tools endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve tools: {str(e)}"
        )

@app.get("/api/tools/{tool_name}")
async def get_tool_details(
    tool_name: str,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Get detailed information about a specific tool."""
    try:
        from mcp_tools.manager import get_tool_manager
        
        tool_manager = get_tool_manager()
        tool_info = tool_manager.get_tool_info(tool_name)
        
        if not tool_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Tool '{tool_name}' not found"
            )
        
        return {"tool": tool_info}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get tool details endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get tool details: {str(e)}"
        )

@app.post("/api/tools/run")
async def run_tool_endpoint(
    request: Dict[str, Any],
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Start a tool execution job."""
    try:
        from mcp_tools.manager import get_tool_manager
        
        # Extract request parameters
        tool_name = request.get("name")
        target = request.get("target")
        args = request.get("args", {})
        safe_mode = request.get("safe_mode", True)
        
        if not tool_name:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Tool name is required"
            )
        
        if not target:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target is required"
            )
        
        tool_manager = get_tool_manager()
        job_id = await tool_manager.run_tool(
            tool_name=tool_name,
            target=target,
            args=args,
            safe_mode=safe_mode
        )
        
        # Log the tool execution attempt
        try:
            from .audit import audit_logger
            audit_logger.log_tool_execution(
                server_id=server_creds.server_id,
                tool_name=tool_name,
                target=target,
                success=True,
                job_id=job_id
            )
        except Exception as audit_error:
            logger.warning(f"Failed to log tool execution: {audit_error}")
        
        return {
            "job_id": job_id,
            "status": "started",
            "tool_name": tool_name,
            "target": target,
            "safe_mode": safe_mode,
            "message": f"Tool {tool_name} started with job ID {job_id}"
        }
        
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Run tool endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start tool: {str(e)}"
        )

@app.get("/api/tools/jobs/{job_id}")
async def get_job_status_endpoint(
    job_id: str,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Get the status and results of a tool execution job."""
    try:
        from mcp_tools.manager import get_tool_manager
        
        tool_manager = get_tool_manager()
        job_status = tool_manager.get_job_status(job_id)
        
        if not job_status:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job '{job_id}' not found"
            )
        
        return {"job": job_status}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get job status endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get job status: {str(e)}"
        )

@app.get("/api/tools/jobs/{job_id}/stream")
async def stream_job_output_endpoint(
    job_id: str,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Stream live output from a running job."""
    try:
        from mcp_tools.manager import get_tool_manager
        from fastapi.responses import StreamingResponse
        
        tool_manager = get_tool_manager()
        
        # Verify job exists
        job_status = tool_manager.get_job_status(job_id)
        if not job_status:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job '{job_id}' not found"
            )
        
        return StreamingResponse(
            tool_manager.stream_job_output(job_id),
            media_type="application/x-ndjson"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Stream job output endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stream job output: {str(e)}"
        )

@app.post("/api/tools/jobs/{job_id}/cancel")
async def cancel_job_endpoint(
    job_id: str,
    server_creds: ServerCredentials = Depends(require_api_key)
):
    """Cancel a running job."""
    try:
        from mcp_tools.manager import get_tool_manager
        
        tool_manager = get_tool_manager()
        success = tool_manager.cancel_job(job_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Job '{job_id}' could not be cancelled (not found or not running)"
            )
        
        return {
            "job_id": job_id,
            "status": "cancelled",
            "message": f"Job {job_id} has been cancelled"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Cancel job endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cancel job: {str(e)}"
        )

# Shutdown event handler
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on server shutdown."""
    logger.info("MCP Kali Server shutting down...")
    
    # Perform any necessary cleanup
    try:
        # Clean up old memory observations (keep last 30 days)
        from .memory import memory_manager
        cleaned = memory_manager.cleanup_old_observations(30)
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} old observations during shutdown")
    except Exception as e:
        logger.error(f"Error during shutdown cleanup: {e}")
    
    logger.info("MCP Kali Server shutdown complete")

# Export the app for uvicorn
__all__ = ["app"]