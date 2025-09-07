package com.burp.mcp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Base MCP message following JSON-RPC 2.0 specification
 */
public class McpMessage {
    
    @JsonProperty("jsonrpc")
    private String jsonrpc = "2.0";
    
    @JsonProperty("id")
    @JsonInclude(JsonInclude.Include.ALWAYS) // Claude Desktop requires id field always present
    private Object id;
    
    @JsonProperty("method")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String method;
    
    @JsonProperty("params")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Object params;
    
    @JsonProperty("result")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Object result;
    
    @JsonProperty("error")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private McpError error;
    
    public McpMessage() {}
    
    public McpMessage(String method, Object params, Object id) {
        this.method = method;
        this.params = params;
        this.id = id;
    }
    
    // Getters and setters
    public String getJsonrpc() { return jsonrpc; }
    public void setJsonrpc(String jsonrpc) { this.jsonrpc = jsonrpc; }
    
    public Object getId() { return id; }
    public void setId(Object id) { this.id = id; }
    
    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }
    
    public Object getParams() { return params; }
    public void setParams(Object params) { this.params = params; }
    
    public Object getResult() { return result; }
    public void setResult(Object result) { this.result = result; }
    
    public McpError getError() { return error; }
    public void setError(McpError error) { this.error = error; }
    
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class McpError {
        @JsonProperty("code")
        private int code;
        
        @JsonProperty("message")
        private String message;
        
        @JsonProperty("data")
        @JsonInclude(JsonInclude.Include.NON_NULL)
        private Object data;
        
        public McpError() {}
        
        public McpError(int code, String message) {
            this.code = code;
            this.message = message;
            // Don't set data field - leave it null so it won't be serialized
        }
        
        // Getters and setters
        public int getCode() { return code; }
        public void setCode(int code) { this.code = code; }
        
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
        
        public Object getData() { return data; }
        public void setData(Object data) { this.data = data; }
    }
}
