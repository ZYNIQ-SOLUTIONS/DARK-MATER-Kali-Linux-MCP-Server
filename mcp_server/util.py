"""
Utility functions for MCP Kali Server.
Includes schema validation, file operations, and common helpers.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
import jsonschema
from jsonschema import validate, ValidationError

logger = logging.getLogger(__name__)

# Schema directory
SCHEMA_DIR = Path(__file__).parent / "schemas" / "tools"

def load_schema(tool_name: str) -> Optional[Dict[str, Any]]:
    """
    Load JSON schema for a tool.
    
    Args:
        tool_name: Name of the tool (e.g., 'net.scan_basic')
        
    Returns:
        Schema dictionary or None if not found
    """
    try:
        # Use string path to avoid Windows path issues
        # Normalize tool name dots to underscores for schema filenames
        normalized_name = tool_name.replace(".", "_")
        schema_file_str = str(SCHEMA_DIR / f"{normalized_name}.json")
        logger.debug(f"Looking for schema file: {schema_file_str}")
        
        # Check using os.path.exists
        import os
        if not os.path.exists(schema_file_str):
            logger.error(f"Schema file not found: {schema_file_str}")
            return None
            
        with open(schema_file_str, 'r', encoding='utf-8') as f:
            schema = json.load(f)
            
        logger.debug(f"Loaded schema for {tool_name}")
        return schema
        
    except Exception as e:
        logger.error(f"Error loading schema for {tool_name}: {e}")
        return None

def validate_tool_args(tool_name: str, args: Dict[str, Any]) -> tuple[bool, Optional[str]]:
    """
    Validate tool arguments against schema.
    
    Args:
        tool_name: Name of the tool
        args: Arguments to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        schema = load_schema(tool_name)
        if not schema:
            return False, f"Schema not found for tool: {tool_name}"
            
        # Validate arguments against schema
        validate(instance=args, schema=schema)
        logger.debug(f"Arguments validated successfully for {tool_name}")
        return True, None
        
    except ValidationError as e:
        error_msg = f"Schema validation failed: {e.message}"
        logger.warning(f"Validation failed for {tool_name}: {error_msg}")
        return False, error_msg
        
    except Exception as e:
        error_msg = f"Validation error: {str(e)}"
        logger.error(f"Unexpected validation error for {tool_name}: {error_msg}")
        return False, error_msg

def get_available_schemas() -> List[str]:
    """
    Get list of available tool schemas.
    
    Returns:
        List of tool names with available schemas
    """
    try:
        if not SCHEMA_DIR.exists():
            logger.warning(f"Schema directory does not exist: {SCHEMA_DIR}")
            return []
            
        schemas = []
        for schema_file in SCHEMA_DIR.glob("*.json"):
            tool_name = schema_file.stem
            schemas.append(tool_name)
            
        logger.debug(f"Found {len(schemas)} available schemas")
        return sorted(schemas)
        
    except Exception as e:
        logger.error(f"Error getting available schemas: {e}")
        return []

def load_all_schemas() -> Dict[str, Dict[str, Any]]:
    """
    Load all available tool schemas.
    
    Returns:
        Dictionary mapping tool names to their schemas
    """
    schemas = {}
    available_tools = get_available_schemas()
    
    for tool_name in available_tools:
        schema = load_schema(tool_name)
        if schema:
            schemas[tool_name] = schema
            
    logger.info(f"Loaded {len(schemas)} tool schemas")
    return schemas

def safe_json_load(file_path: Path, default: Any = None) -> Any:
    """
    Safely load JSON file with fallback to default.
    
    Args:
        file_path: Path to JSON file
        default: Default value to return if file cannot be loaded
        
    Returns:
        Loaded JSON data or default value
    """
    try:
        if not file_path.exists():
            logger.debug(f"File does not exist: {file_path}")
            return default
            
        with open(file_path, 'r') as f:
            return json.load(f)
            
    except Exception as e:
        logger.error(f"Error loading JSON from {file_path}: {e}")
        return default

def safe_json_save(file_path: Path, data: Any, create_dirs: bool = True) -> bool:
    """
    Safely save data to JSON file.
    
    Args:
        file_path: Path to save JSON file
        data: Data to save
        create_dirs: Whether to create parent directories
        
    Returns:
        True if successful, False otherwise
    """
    try:
        if create_dirs:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
            
        logger.debug(f"Saved JSON data to {file_path}")
        return True
        
    except Exception as e:
        logger.error(f"Error saving JSON to {file_path}: {e}")
        return False

def truncate_output(text: str, max_length: int = 10000) -> str:
    """
    Truncate text output to prevent excessive response sizes.
    
    Args:
        text: Text to truncate
        max_length: Maximum length to keep
        
    Returns:
        Truncated text with indicator if truncated
    """
    if len(text) <= max_length:
        return text
        
    truncated = text[:max_length]
    truncated += f"\n\n[Output truncated - showing first {max_length} characters of {len(text)} total]"
    return truncated

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal and invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename safe for filesystem use
    """
    import re
    
    # Remove any path components
    filename = Path(filename).name
    
    # Replace invalid characters with underscores
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove any remaining non-printable characters
    filename = ''.join(c for c in filename if c.isprintable())
    
    # Ensure filename is not empty
    if not filename:
        filename = "unnamed_file"
        
    return filename

def generate_run_id() -> str:
    """
    Generate a unique run ID for tool executions.
    
    Returns:
        Unique run ID string
    """
    import uuid
    import time
    
    # Use timestamp + short UUID for readability and uniqueness
    timestamp = int(time.time())
    short_uuid = str(uuid.uuid4())[:8]
    
    return f"{timestamp}_{short_uuid}"

def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human-readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string
    """
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"

def get_file_size_str(file_path: Path) -> str:
    """
    Get human-readable file size string.
    
    Args:
        file_path: Path to file
        
    Returns:
        Formatted file size string
    """
    try:
        if not file_path.exists():
            return "0 B"
            
        size = file_path.stat().st_size
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
            
        return f"{size:.1f} TB"
        
    except Exception as e:
        logger.error(f"Error getting file size for {file_path}: {e}")
        return "unknown"