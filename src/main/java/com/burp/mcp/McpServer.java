package com.burp.mcp;

import com.burp.mcp.model.McpMessage;
import com.burp.mcp.protocol.BurpIntegration;
import com.burp.mcp.protocol.McpProtocolHandler;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.util.concurrent.Executors;

/**
 * Main MCP Server class that provides both stdio and HTTP transport
 * Compatible with Claude Desktop MCP integration
 */
public class McpServer {
    
    private static final Logger logger = LoggerFactory.getLogger(McpServer.class);
    private static final int HTTP_PORT = 5001;
    
    private final ObjectMapper objectMapper;
    private final McpProtocolHandler protocolHandler;
    private HttpServer httpServer;
    
    public McpServer() {
        // Configure ObjectMapper to exclude null values for minimal JSON-RPC responses
        this.objectMapper = new ObjectMapper();
        this.objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        
        var burpIntegration = new BurpIntegration();
        this.protocolHandler = new McpProtocolHandler(burpIntegration);
    }
    
    public McpServer(BurpIntegration burpIntegration) {
        // Configure ObjectMapper to exclude null values for minimal JSON-RPC responses
        this.objectMapper = new ObjectMapper();
        this.objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        
        this.protocolHandler = new McpProtocolHandler(burpIntegration);
    }
    
    /**
     * Check if live mode is enabled through command line args or environment
     */
    private static boolean checkLiveMode(String[] args) {
        // Check command line arguments
        for (String arg : args) {
            if ("--live-mode".equals(arg) || "--live".equals(arg)) {
                return true;
            }
        }
        
        // Check environment variables
        String integrationMode = System.getenv("BURP_INTEGRATION_MODE");
        if ("LIVE".equalsIgnoreCase(integrationMode)) {
            return true;
        }
        
        // Check if running inside BurpSuite (would have BurpSuite classes available)
        try {
            Class.forName("burp.api.montoya.MontoyaApi");
            return true; // Running inside BurpSuite
        } catch (ClassNotFoundException e) {
            return false; // Standalone mode
        }
    }
    
    public static void main(String[] args) {
        // Determine integration mode
        boolean liveMode = checkLiveMode(args);
        if (liveMode) {
            logger.info("Starting MCP server in LIVE integration mode");
        } else {
            logger.info("Starting MCP server in STANDALONE mode with mock data");
        }
        
        McpServer server = new McpServer();
        
        // Check command line arguments to determine transport mode
        if (args.length > 0 && ("--stdio".equals(args[0]) || "stdio".equals(args[0]))) {
            logger.info("Starting MCP server in stdio mode");
            server.startStdioMode();
        } else {
            logger.info("Starting MCP server in HTTP mode on port {}", HTTP_PORT);
            server.startHttpServer();
        }
    }
    
    /**
     * Start server in stdio mode for Claude Desktop integration
     */
    public void startStdioMode() {
        logger.info("MCP Server started in stdio mode");
        
        try (Scanner scanner = new Scanner(System.in)) {
            while (scanner.hasNextLine()) {
                String inputLine = scanner.nextLine().trim();
                
                if (inputLine.isEmpty()) {
                    continue;
                }
                
                try {
                    // Parse the JSON-RPC request
                    McpMessage request = objectMapper.readValue(inputLine, McpMessage.class);
                    logger.debug("Received request: {}", request.getMethod());
                    
                    // Process the request
                    McpMessage response = protocolHandler.handleRequest(request);
                    
                    // Send response to stdout
                    String responseJson = objectMapper.writeValueAsString(response);
                    System.out.println(responseJson);
                    System.out.flush();
                    
                    logger.debug("Sent response for: {}", request.getMethod());
                    
                } catch (Exception e) {
                    logger.error("Error processing stdio request", e);
                    
                    // Send error response
                    McpMessage errorResponse = new McpMessage();
                    errorResponse.setError(new McpMessage.McpError(-32700, "Parse error"));
                    
                    try {
                        String errorJson = objectMapper.writeValueAsString(errorResponse);
                        System.out.println(errorJson);
                        System.out.flush();
                    } catch (Exception ex) {
                        logger.error("Failed to send error response", ex);
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Fatal error in stdio mode", e);
            System.exit(1);
        }
    }
    
    /**
     * Start HTTP server on localhost:5001 (default port)
     */
    public void startHttpServer() {
        startHttpServer(HTTP_PORT);
    }
    
    /**
     * Start HTTP server on specified port
     */
    public void startHttpServer(int port) {
        try {
            httpServer = HttpServer.create(new InetSocketAddress("localhost", port), 0);
            httpServer.createContext("/mcp", new McpHttpHandler());
            httpServer.setExecutor(Executors.newFixedThreadPool(4));
            
            httpServer.start();
            logger.info("MCP HTTP server started on http://localhost:{}/mcp", port);
            
            // Keep the server running
            Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown));
            
            // Block main thread
            synchronized (this) {
                try {
                    wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            
        } catch (IOException e) {
            logger.error("Failed to start HTTP server on port {}", port, e);
            System.exit(1);
        }
    }
    
    public void shutdown() {
        if (httpServer != null) {
            logger.info("Shutting down MCP server...");
            httpServer.stop(5);
            synchronized (this) {
                notifyAll(); // Wake up blocked main thread
            }
        }
    }
    
    /**
     * HTTP handler for MCP requests
     */
    private class McpHttpHandler implements HttpHandler {
        
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // Set CORS headers
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, OPTIONS");
            exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type");
            
            if ("OPTIONS".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }
            
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
                return;
            }
            
            try {
                // Read request body
                String requestBody = new String(
                    exchange.getRequestBody().readAllBytes(),
                    StandardCharsets.UTF_8
                );
                
                logger.debug("HTTP request: {}", requestBody);
                
                // Parse and process request
                McpMessage request = objectMapper.readValue(requestBody, McpMessage.class);
                McpMessage response = protocolHandler.handleRequest(request);
                
                // Send response
                String responseJson = objectMapper.writeValueAsString(response);
                
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, responseJson.getBytes(StandardCharsets.UTF_8).length);
                
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(responseJson.getBytes(StandardCharsets.UTF_8));
                }
                
                logger.debug("HTTP response sent for: {}", request.getMethod());
                
            } catch (Exception e) {
                logger.error("Error handling HTTP request", e);
                sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage());
            }
        }
        
        private void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
            McpMessage errorResponse = new McpMessage();
            errorResponse.setError(new McpMessage.McpError(-32603, message));
            
            String errorJson = objectMapper.writeValueAsString(errorResponse);
            
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(statusCode, errorJson.getBytes(StandardCharsets.UTF_8).length);
            
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(errorJson.getBytes(StandardCharsets.UTF_8));
            }
        }
    }
}
