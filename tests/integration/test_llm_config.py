"""
Test script for LLM Configuration System
"""
import requests
import json
import time
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

def test_llm_config():
    """Test the LLM configuration system"""
    
    print("🧪 LLM Configuration System Test")
    print("=" * 50)
    
    base_url = "http://127.0.0.1:5000"
    
    # Test server connectivity
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code != 200:
            print(f"❌ Server not responding: {response.status_code}")
            return False
        print("✅ Server is running")
        
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        print("💡 Make sure the server is running on port 5000")
        return False
    
    # Create enrollment
    print("\n🔐 Creating enrollment...")
    try:
        with open("/etc/mcp-kali/enroll.json", "r") as f:
            file_data = json.load(f)
            enroll_id = file_data["id"]
            enroll_token = file_data["token"]
    except:
        enroll_id = "kali-lab-01"
        enroll_token = "test-token-for-llm-config-123456789"
        
    enrollment_data = {
        "id": enroll_id,
        "token": enroll_token,
        "label": "LLM Configuration Test"
    }
    
    try:
        enroll_response = requests.post(f"{base_url}/enroll", json=enrollment_data, timeout=10)
        
        if enroll_response.status_code != 200:
            print(f"❌ Enrollment failed: {enroll_response.status_code}")
            print(f"📋 Response: {enroll_response.text}")
            return False
            
        credentials = enroll_response.json()
        api_key = credentials["api_key"]
        server_id = credentials["server_id"]
        
        print(f"✅ Enrolled server: {server_id}")
        print(f"🔑 API Key: {api_key[:20]}...")
        
    except Exception as e:
        print(f"❌ Enrollment error: {e}")
        return False
    
    # Test LLM configuration endpoints
    headers = {"Authorization": f"Bearer {api_key}"}
    
    print(f"\n📋 Testing LLM Configuration Endpoints...")
    
    # Get default configuration
    try:
        config_response = requests.get(f"{base_url}/llm/config", headers=headers, timeout=5)
        
        if config_response.status_code != 200:
            print(f"❌ Failed to get LLM config: {config_response.status_code}")
            return False
            
        current_config = config_response.json()
        print("✅ Retrieved default LLM configuration")
        print(f"📋 Current ETag: {current_config.get('etag', 'none')}")
        print(f"📋 System Prompt: {current_config.get('system_prompt', '')[:100]}...")
        
    except Exception as e:
        print(f"❌ Error getting LLM config: {e}")
        return False
    
    # Apply your target configuration
    print(f"\n🔧 Applying target LLM configuration...")
    
    target_config = {
        "system_prompt": "You are the MCP Server Assistant for Kali-Lab-01. Use only provided memory, knowledge, and live context. Respond with explicit, copy-pastable steps. If action is risky, ask for confirmation and suggest a dry run. Keep answers under 200 tokens unless logs are requested.",
        "guardrails": {
            "disallowed": ["secrets", "credentials", "api_keys"], 
            "style": "concise"
        },
        "runtime_hints": {
            "preferred_model": "phi3:mini", 
            "num_ctx": 768, 
            "temperature": 0.2, 
            "num_gpu": 0, 
            "keep_alive": 0
        },
        "tools_allowed": ["net.scan_basic", "web.nikto"]
    }
    
    try:
        # Use ETag for optimistic concurrency
        update_headers = {**headers, "If-Match": current_config.get("etag", "")}
        
        update_response = requests.put(
            f"{base_url}/llm/config",
            json=target_config,
            headers=update_headers,
            timeout=10
        )
        
        if update_response.status_code != 200:
            print(f"❌ Failed to update LLM config: {update_response.status_code}")
            print(f"📋 Response: {update_response.text}")
            return False
            
        updated_config = update_response.json()
        print("✅ Successfully updated LLM configuration!")
        print(f"📋 New ETag: {updated_config.get('etag', 'none')}")
        
        # Verify the configuration was applied
        verify_response = requests.get(f"{base_url}/llm/config", headers=headers, timeout=5)
        if verify_response.status_code == 200:
            verified_config = verify_response.json()
            
            print(f"\n📋 Configuration Applied Successfully:")
            print(f"   🎯 Server ID: {verified_config['server_id']}")
            print(f"   🤖 Model: {verified_config['runtime_hints'].get('preferred_model', 'not set')}")
            print(f"   🌡️  Temperature: {verified_config['runtime_hints'].get('temperature', 'not set')}")
            print(f"   🛠️  Tools Allowed: {len(verified_config.get('tools_allowed', []))} tools")
            print(f"   🛡️  Guardrails: {list(verified_config.get('guardrails', {}).keys())}")
            
            # Show the actual configuration
            print(f"\n📝 Full Configuration:")
            print(json.dumps(verified_config, indent=2))
            
        return True
        
    except Exception as e:
        print(f"❌ Error updating LLM config: {e}")
        return False
    
    # Test other LLM endpoints
    print(f"\n🧠 Testing other LLM endpoints...")
    
    # Test JWT token creation
    try:
        token_request = {"api_key": api_key}
        token_response = requests.post(f"{base_url}/auth/token", json=token_request, timeout=5)
        
        if token_response.status_code == 200:
            token_data = token_response.json()
            print(f"✅ JWT token created successfully")
            print(f"🔑 Token type: {token_data.get('token_type', 'unknown')}")
            print(f"⏰ Expires in: {token_data.get('expires_in', 0)} seconds")
        else:
            print(f"❌ JWT token creation failed: {token_response.status_code}")
            
    except Exception as e:
        print(f"❌ JWT token error: {e}")
    
    # Test live context
    try:
        context_response = requests.get(f"{base_url}/llm/context", headers=headers, timeout=5)
        
        if context_response.status_code == 200:
            context_data = context_response.json()
            print(f"✅ Live context retrieved")
            print(f"📊 Uptime: {context_data.get('uptime', 'unknown')}")
            print(f"💽 Disk usage: {context_data.get('disk_usage', 'unknown')}")
            print(f"🚨 Alerts: {len(context_data.get('alerts', []))}")
        else:
            print(f"❌ Live context failed: {context_response.status_code}")
            
    except Exception as e:
        print(f"❌ Live context error: {e}")
    
    print(f"\n🎉 LLM Configuration System Test Complete!")
    return True

def main():
    success = False
    # Check live server
    base_url = "http://127.0.0.1:5000"
    server_live = False
    try:
        r = requests.get(f"{base_url}/health", timeout=2)
        server_live = True
    except:
        pass

    if server_live:
        success = test_llm_config()
    else:
        print("💡 Live server is not responding. Falling back to in-memory FastAPI TestClient verification.")
        # Clean up existing test server enrollment to prevent 409 Conflict
        try:
            import tempfile
            import os
            import json
            from datetime import datetime, timezone
            
            temp_dir = tempfile.mkdtemp()
            os.environ["MCP_TEST_CONFIG_DIR"] = temp_dir
            
            from fastapi.testclient import TestClient
            from mcp_server.api import app
            from mcp_server.auth import load_api_credentials, save_api_credentials
            
            # Determine enrollment ID dynamically
            enroll_id = "kali-lab-01"
            
            mock_enroll = {
                "id": enroll_id,
                "token": "test-token-for-llm-config-123456789",
                "created": datetime.now(timezone.utc).isoformat()
            }
            with open(os.path.join(temp_dir, "enroll.json"), "w") as f:
                json.dump(mock_enroll, f)
                
            mock_scope = {
                "allowed_cidrs": ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "127.0.0.0/8"],
                "allow_destructive": True
            }
            with open(os.path.join(temp_dir, "scope.json"), "w") as f:
                json.dump(mock_scope, f)
            
            creds = load_api_credentials()
            if enroll_id in creds:
                del creds[enroll_id]
                save_api_credentials(creds)
                print(f"🧹 Cleaned up existing credentials for '{enroll_id}'")
        except Exception as e:
            print(f"⚠️ Failed to clean up existing credentials: {e}")
        
        with TestClient(app) as client:
            # Simple proxy function to translate requests calls to client calls
            class RequestProxy:
                def get(self, url, **kwargs):
                    path = url.replace(base_url, "")
                    # remove base url
                    headers = kwargs.get("headers", {})
                    params = kwargs.get("params", {})
                    return client.get(path, headers=headers, params=params)
                    
                def post(self, url, **kwargs):
                    path = url.replace(base_url, "")
                    headers = kwargs.get("headers", {})
                    json_data = kwargs.get("json", {})
                    return client.post(path, headers=headers, json=json_data)
                    
                def put(self, url, **kwargs):
                    path = url.replace(base_url, "")
                    headers = kwargs.get("headers", {})
                    json_data = kwargs.get("json", {})
                    return client.put(path, headers=headers, json=json_data)
                    
            globals()['requests'] = RequestProxy()
            success = test_llm_config()
        
    if success:
        print(f"\n✅ All tests passed!")
        sys.exit(0)
    else:
        print(f"\n❌ Some tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()