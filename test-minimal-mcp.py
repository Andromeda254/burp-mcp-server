#!/usr/bin/env python3
import json
import sys

def handle_initialize(request):
    return {
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": True}
            },
            "serverInfo": {
                "name": "test-minimal-mcp",
                "version": "1.0.0"
            }
        }
    }

def handle_tools_list(request):
    return {
        "jsonrpc": "2.0", 
        "id": request["id"],
        "result": {
            "tools": [
                {
                    "name": "simple_test",
                    "description": "A simple test tool",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "message": {
                                "type": "string",
                                "description": "A test message"
                            }
                        },
                        "required": ["message"]
                    }
                }
            ]
        }
    }

def handle_tools_call(request):
    return {
        "jsonrpc": "2.0",
        "id": request["id"], 
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": "Test successful!"
                }
            ]
        }
    }

def handle_unsupported(request):
    return {
        "jsonrpc": "2.0",
        "id": request["id"],
        "error": {
            "code": -32601,
            "message": f"Method not found: {request['method']}"
        }
    }

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
            
        try:
            request = json.loads(line)
            
            if request["method"] == "initialize":
                response = handle_initialize(request)
            elif request["method"] == "tools/list":
                response = handle_tools_list(request)
            elif request["method"] == "tools/call":
                response = handle_tools_call(request)
            else:
                response = handle_unsupported(request)
                
            print(json.dumps(response, separators=(',', ':')))
            sys.stdout.flush()
            
        except Exception as e:
            error_response = {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }
            print(json.dumps(error_response, separators=(',', ':')))
            sys.stdout.flush()

if __name__ == "__main__":
    main()
