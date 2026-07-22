#!/usr/bin/env python3
"""
Test the net.scan_basic.json schema file.
"""

import json
import jsonschema
from pathlib import Path

def test_schema():
    """Test the schema file."""
    schema_path = Path('mcp_server/schemas/tools/net_scan_basic.json')
    print(f'📋 Testing schema file: {schema_path}')
    print(f'File exists: {schema_path.exists()}')

    try:
        with open(schema_path, 'r') as f:
            schema = json.load(f)
        
        print('✅ Schema loaded successfully')
        print(f'Title: {schema.get("title", "N/A")}')
        print(f'Description: {schema.get("description", "N/A")[:60]}...')
        print(f'Required fields: {schema.get("required", [])}')
        
        # Validate the schema itself
        jsonschema.Draft7Validator.check_schema(schema)
        print('✅ Schema validation passed')
        
        # Test with sample data
        test_cases = [
            {
                'target': '127.0.0.1',
                'fast': True
            },
            {
                'target': '192.168.1.0/24',
                'ports': '22,80,443',
                'service_detection': True
            },
            {
                'target': 'scanme.nmap.org',
                'ports': '1-1000',
                'timing_template': 3
            }
        ]
        
        for i, test_data in enumerate(test_cases, 1):
            try:
                jsonschema.validate(test_data, schema)
                print(f'✅ Test case {i} validation passed')
            except jsonschema.ValidationError as e:
                print(f'❌ Test case {i} validation failed: {e.message}')
        
        print('\n🎉 Schema is working correctly!')
        return True
        
    except json.JSONDecodeError as e:
        print(f'❌ JSON parsing error: {e}')
        return False
    except jsonschema.SchemaError as e:
        print(f'❌ Schema validation error: {e}')
        return False
    except Exception as e:
        print(f'❌ Unexpected error: {e}')
        return False

if __name__ == "__main__":
    test_schema()