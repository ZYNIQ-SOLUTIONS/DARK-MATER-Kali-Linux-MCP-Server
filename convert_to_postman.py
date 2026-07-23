import json
from mcp_server.api import app

openapi = app.openapi()

postman_collection = {
    "info": {
        "name": "DARK MATTER MCP Server API",
        "description": "API Endpoints for Kali Linux MCP Server",
        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
    },
    "variable": [
        {"key": "base_url", "value": "http://localhost:5000", "type": "string"},
        {"key": "api_key", "value": "your_api_key_here", "type": "string"}
    ],
    "item": []
}

for path, methods in openapi.get("paths", {}).items():
    for method, details in methods.items():
        body_dict = {}
        if "requestBody" in details:
            try:
                schema_ref = details["requestBody"]["content"]["application/json"]["schema"]
                ref_name = schema_ref.get("$ref", "").split("/")[-1]
                if ref_name:
                    schema = openapi["components"]["schemas"].get(ref_name, {})
                    example = {}
                    if "properties" in schema:
                        for prop, prop_details in schema["properties"].items():
                            example[prop] = prop_details.get("default", prop_details.get("type", "string"))
                    body_dict = {
                        "mode": "raw",
                        "raw": json.dumps(example, indent=4),
                        "options": {
                            "raw": {
                                "language": "json"
                            }
                        }
                    }
            except Exception as e:
                pass

        url_variables = []
        if "parameters" in details:
            for param in details["parameters"]:
                if param["in"] == "path":
                    url_variables.append({
                        "key": param["name"],
                        "value": f"<{param['name']}>"
                    })

        url_path = [p for p in path.split("/") if p]
        
        # Determine query params
        query_params = []
        if "parameters" in details:
            for param in details["parameters"]:
                if param["in"] == "query":
                    query_params.append({
                        "key": param["name"],
                        "value": param.get("schema", {}).get("default", "") if param.get("schema") else ""
                    })

        postman_item = {
            "name": details.get("summary", path),
            "request": {
                "method": method.upper(),
                "header": [
                    {
                        "key": "Authorization",
                        "value": "Bearer {{api_key}}",
                        "type": "text"
                    }
                ],
                "url": {
                    "raw": f"{{{{base_url}}}}{path}",
                    "host": ["{{base_url}}"],
                    "path": url_path,
                    "variable": url_variables,
                    "query": query_params
                }
            }
        }
        if body_dict:
            postman_item["request"]["body"] = body_dict

        postman_collection["item"].append(postman_item)

with open("openapi.json", "w") as f:
    json.dump(postman_collection, f, indent=4)
    
print("Successfully generated openapi.json in Postman Collection format")
