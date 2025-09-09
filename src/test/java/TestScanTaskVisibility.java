package test;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.Crawl;

/**
 * Simple test extension to verify if Montoya API scan tasks appear in BurpSuite main UI
 */
public class TestScanTaskVisibility implements BurpExtension {
    
    @Override
    public void initialize(MontoyaApi api) {
        api.logging().logToOutput("=== TEST SCAN TASK VISIBILITY ===");
        api.logging().logToOutput("Extension loaded successfully!");
        
        try {
            // Test URL - you can change this
            String testUrl = "https://example.com";
            
            api.logging().logToOutput("🚀 Testing scan task creation for: " + testUrl);
            
            // Create HTTP request
            HttpRequest request = HttpRequest.httpRequestFromUrl(testUrl);
            api.logging().logToOutput("✓ Created HTTP request");
            
            // Add to scope
            api.scope().includeInScope(request.url());
            api.logging().logToOutput("✓ Added to scope");
            
            // Send initial request
            var response = api.http().sendRequest(request);
            api.logging().logToOutput("✓ Sent initial request - Response: " + response.statusCode());
            
            // Create configurations
            CrawlConfiguration crawlConfig = CrawlConfiguration.crawlConfiguration(testUrl);
            AuditConfiguration auditConfig = AuditConfiguration.auditConfiguration(
                BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS);
            
            api.logging().logToOutput("✓ Created configurations");
            
            // Start crawl task
            api.logging().logToOutput("🔍 Starting crawl task...");
            Crawl crawlTask = api.scanner().startCrawl(crawlConfig);
            api.logging().logToOutput("✅ Crawl task started - Type: " + crawlTask.getClass().getSimpleName());
            
            // Start audit task
            api.logging().logToOutput("🔍 Starting audit task...");
            Audit auditTask = api.scanner().startAudit(auditConfig);
            api.logging().logToOutput("✅ Audit task started - Type: " + auditTask.getClass().getSimpleName());
            
            // Add request to audit task
            try {
                auditTask.addRequest(request);
                api.logging().logToOutput("✓ Added request to audit task");
            } catch (Exception e) {
                api.logging().logToOutput("⚠ Could not add request to audit: " + e.getMessage());
            }
            
            // Monitor tasks
            new Thread(() -> {
                try {
                    Thread.sleep(3000);
                    api.logging().logToOutput("📊 TASK STATUS AFTER 3 SECONDS:");
                    api.logging().logToOutput("  Crawl status: " + crawlTask.statusMessage());
                    api.logging().logToOutput("  Crawl requests: " + crawlTask.requestCount());
                    api.logging().logToOutput("  Crawl errors: " + crawlTask.errorCount());
                    api.logging().logToOutput("  Audit status: " + auditTask.statusMessage());
                    api.logging().logToOutput("  Audit requests: " + auditTask.requestCount());
                    api.logging().logToOutput("  Audit errors: " + auditTask.errorCount());
                    api.logging().logToOutput("  Issues found: " + auditTask.issues().size());
                    
                    api.logging().logToOutput("🎯 CHECK BURP SCANNER > DASHBOARD > TASKS NOW!");
                    api.logging().logToOutput("   Look for active crawl and audit tasks");
                    
                } catch (Exception e) {
                    api.logging().logToOutput("❌ Error monitoring tasks: " + e.getMessage());
                    e.printStackTrace();
                }
            }).start();
            
            api.logging().logToOutput("=== TEST COMPLETED ===");
            api.logging().logToOutput("Check Scanner > Dashboard > Tasks for visible tasks");
            
        } catch (Exception e) {
            api.logging().logToOutput("❌ Test failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
