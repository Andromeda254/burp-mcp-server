package com.burp.mcp.browser;

import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.awt.Rectangle;
import java.awt.Graphics2D;
import java.awt.Color;
import java.awt.RenderingHints;
import java.awt.Point;
import java.awt.geom.AffineTransform;
import java.awt.image.AffineTransformOp;
import java.util.Stack;
import java.util.UUID;

/**
 * Advanced screenshot capture system with image comparison and analysis capabilities
 * Integrates with WebDriver for automated browser screenshot capture
 * Implements classic computer vision techniques for image analysis
 */
public class ScreenshotCapture {
    
    private static final Logger logger = LoggerFactory.getLogger(ScreenshotCapture.class);
    
    // Screenshot storage
    private static final Map<String, ScreenshotData> screenshotCache = new ConcurrentHashMap<>();
    private static final String DEFAULT_SCREENSHOT_DIR = "screenshots";
    
    // Image comparison thresholds
    private static final double DEFAULT_SIMILARITY_THRESHOLD = 0.95;
    private static final double PIXEL_TOLERANCE = 0.1;
    private static final int MAX_CACHE_SIZE = 100;
    
    /**
     * Screenshot configuration
     */
    public static class ScreenshotConfig {
        private boolean saveToFile = true;
        private boolean includeInCache = true;
        private String outputDirectory = DEFAULT_SCREENSHOT_DIR;
        private String imageFormat = "PNG";
        private boolean fullPage = false;
        private boolean includeMetadata = true;
        private double compressionQuality = 1.0;
        private List<String> elementsToHighlight = new ArrayList<>();
        private List<String> elementsToHide = new ArrayList<>();
        private boolean captureViewportOnly = false;
        private int maxWidth = 0; // 0 means no limit
        private int maxHeight = 0; // 0 means no limit
        
        // Getters and setters
        public boolean isSaveToFile() { return saveToFile; }
        public void setSaveToFile(boolean saveToFile) { this.saveToFile = saveToFile; }
        
        public boolean isIncludeInCache() { return includeInCache; }
        public void setIncludeInCache(boolean includeInCache) { this.includeInCache = includeInCache; }
        
        public String getOutputDirectory() { return outputDirectory; }
        public void setOutputDirectory(String outputDirectory) { this.outputDirectory = outputDirectory; }
        
        public String getImageFormat() { return imageFormat; }
        public void setImageFormat(String imageFormat) { this.imageFormat = imageFormat; }
        
        public boolean isFullPage() { return fullPage; }
        public void setFullPage(boolean fullPage) { this.fullPage = fullPage; }
        
        public boolean isIncludeMetadata() { return includeMetadata; }
        public void setIncludeMetadata(boolean includeMetadata) { this.includeMetadata = includeMetadata; }
        
        public double getCompressionQuality() { return compressionQuality; }
        public void setCompressionQuality(double compressionQuality) { this.compressionQuality = compressionQuality; }
        
        public List<String> getElementsToHighlight() { return elementsToHighlight; }
        public void setElementsToHighlight(List<String> elementsToHighlight) { this.elementsToHighlight = elementsToHighlight; }
        
        public List<String> getElementsToHide() { return elementsToHide; }
        public void setElementsToHide(List<String> elementsToHide) { this.elementsToHide = elementsToHide; }
        
        public boolean isCaptureViewportOnly() { return captureViewportOnly; }
        public void setCaptureViewportOnly(boolean captureViewportOnly) { this.captureViewportOnly = captureViewportOnly; }
        
        public int getMaxWidth() { return maxWidth; }
        public void setMaxWidth(int maxWidth) { this.maxWidth = maxWidth; }
        
        public int getMaxHeight() { return maxHeight; }
        public void setMaxHeight(int maxHeight) { this.maxHeight = maxHeight; }
    }
    
    /**
     * Screenshot data container
     */
    public static class ScreenshotData {
        private String id;
        private String sessionId;
        private String url;
        private String title;
        private long timestamp;
        private byte[] imageData;
        private String imageFormat;
        private int width;
        private int height;
        private Map<String, Object> metadata;
        private String filePath;
        
        public ScreenshotData() {
            this.id = generateScreenshotId();
            this.timestamp = System.currentTimeMillis();
            this.metadata = new HashMap<>();
        }
        
        // Getters and setters
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        
        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }
        
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        
        public String getTitle() { return title; }
        public void setTitle(String title) { this.title = title; }
        
        public long getTimestamp() { return timestamp; }
        public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
        
        public byte[] getImageData() { return imageData; }
        public void setImageData(byte[] imageData) { this.imageData = imageData; }
        
        public String getImageFormat() { return imageFormat; }
        public void setImageFormat(String imageFormat) { this.imageFormat = imageFormat; }
        
        public int getWidth() { return width; }
        public void setWidth(int width) { this.width = width; }
        
        public int getHeight() { return height; }
        public void setHeight(int height) { this.height = height; }
        
        public Map<String, Object> getMetadata() { return metadata; }
        public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
        
        public String getFilePath() { return filePath; }
        public void setFilePath(String filePath) { this.filePath = filePath; }
    }
    
    /**
     * Image comparison result
     */
    public static class ImageComparisonResult {
        private double similarity;
        private List<Rectangle> differences;
        private BufferedImage diffImage;
        private Map<String, Object> metrics;
        private boolean passed;
        private double threshold;
        
        public ImageComparisonResult() {
            this.differences = new ArrayList<>();
            this.metrics = new HashMap<>();
        }
        
        // Getters and setters
        public double getSimilarity() { return similarity; }
        public void setSimilarity(double similarity) { this.similarity = similarity; }
        
        public List<Rectangle> getDifferences() { return differences; }
        public void setDifferences(List<Rectangle> differences) { this.differences = differences; }
        
        public BufferedImage getDiffImage() { return diffImage; }
        public void setDiffImage(BufferedImage diffImage) { this.diffImage = diffImage; }
        
        public Map<String, Object> getMetrics() { return metrics; }
        public void setMetrics(Map<String, Object> metrics) { this.metrics = metrics; }
        
        public boolean isPassed() { return passed; }
        public void setPassed(boolean passed) { this.passed = passed; }
        
        public double getThreshold() { return threshold; }
        public void setThreshold(double threshold) { this.threshold = threshold; }
    }
    
    /**
     * Capture screenshot using WebDriver
     */
    public static CompletableFuture<ScreenshotData> captureScreenshot(WebDriver driver, ScreenshotConfig config) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                logger.info("Capturing screenshot with config: fullPage={}, format={}", 
                    config.isFullPage(), config.getImageFormat());
                
                ScreenshotData screenshot = new ScreenshotData();
                screenshot.setUrl(driver.getCurrentUrl());
                screenshot.setTitle(driver.getTitle());
                screenshot.setImageFormat(config.getImageFormat());
                
                // Hide elements if specified
                hideElements(driver, config.getElementsToHide());
                
                // Highlight elements if specified
                highlightElements(driver, config.getElementsToHighlight());
                
                // Capture screenshot based on configuration
                byte[] screenshotData;
                if (config.isFullPage()) {
                    screenshotData = captureFullPageScreenshot(driver, config);
                } else if (!config.getElementsToHighlight().isEmpty()) {
                    screenshotData = captureElementScreenshot(driver, config.getElementsToHighlight().get(0), config);
                } else {
                    screenshotData = captureViewportScreenshot(driver, config);
                }
                
                // Process image data
                BufferedImage image = ImageIO.read(new ByteArrayInputStream(screenshotData));
                if (image == null) {
                    throw new ScreenshotException("Failed to decode screenshot image");
                }
                
                screenshot.setWidth(image.getWidth());
                screenshot.setHeight(image.getHeight());
                
                // Resize if needed
                if (config.getMaxWidth() > 0 || config.getMaxHeight() > 0) {
                    image = resizeImage(image, config.getMaxWidth(), config.getMaxHeight());
                    screenshotData = imageToByteArray(image, config.getImageFormat());
                    screenshot.setWidth(image.getWidth());
                    screenshot.setHeight(image.getHeight());
                }
                
                screenshot.setImageData(screenshotData);
                
                // Add metadata
                if (config.isIncludeMetadata()) {
                    addMetadata(screenshot, driver, config);
                }
                
                // Save to file if configured
                if (config.isSaveToFile()) {
                    saveScreenshotToFile(screenshot, config);
                }
                
                // Add to cache if configured
                if (config.isIncludeInCache()) {
                    addToCache(screenshot);
                }
                
                // Restore hidden elements
                showElements(driver, config.getElementsToHide());
                
                logger.info("Screenshot captured successfully: {}x{}, size={}KB", 
                    screenshot.getWidth(), screenshot.getHeight(), screenshotData.length / 1024);
                
                return screenshot;
                
            } catch (Exception e) {
                logger.error("Screenshot capture failed: {}", e.getMessage(), e);
                throw new ScreenshotException("Failed to capture screenshot", e);
            }
        }).orTimeout(30, TimeUnit.SECONDS);
    }
    
    /**
     * Capture full page screenshot (including content below the fold)
     */
    private static byte[] captureFullPageScreenshot(WebDriver driver, ScreenshotConfig config) throws IOException {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        
        // Get page dimensions
        long pageHeight = (Long) js.executeScript("return Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)");
        long pageWidth = (Long) js.executeScript("return Math.max(document.body.scrollWidth, document.documentElement.scrollWidth)");
        long viewportHeight = (Long) js.executeScript("return window.innerHeight");
        
        // If page fits in viewport, use regular screenshot
        if (pageHeight <= viewportHeight) {
            return ((TakesScreenshot) driver).getScreenshotAs(OutputType.BYTES);
        }
        
        // Calculate number of screenshots needed
        int screenshots = (int) Math.ceil((double) pageHeight / viewportHeight);
        List<BufferedImage> screenshotParts = new ArrayList<>();
        
        // Capture screenshots scrolling down the page
        for (int i = 0; i < screenshots; i++) {
            long scrollY = i * viewportHeight;
            
            // Scroll to position
            js.executeScript("window.scrollTo(0, " + scrollY + ")");
            
            // Wait for scroll to complete
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new ScreenshotException("Screenshot capture interrupted", e);
            }
            
            // Capture screenshot
            byte[] screenshotData = ((TakesScreenshot) driver).getScreenshotAs(OutputType.BYTES);
            BufferedImage screenshot = ImageIO.read(new ByteArrayInputStream(screenshotData));
            screenshotParts.add(screenshot);
        }
        
        // Stitch screenshots together
        BufferedImage fullPageImage = stitchImages(screenshotParts, (int) pageWidth, (int) pageHeight);
        
        // Reset scroll position
        js.executeScript("window.scrollTo(0, 0)");
        
        return imageToByteArray(fullPageImage, config.getImageFormat());
    }
    
    /**
     * Capture screenshot of specific element
     */
    private static byte[] captureElementScreenshot(WebDriver driver, String selector, ScreenshotConfig config) throws IOException {
        try {
            WebElement element = driver.findElement(By.cssSelector(selector));
            return element.getScreenshotAs(OutputType.BYTES);
        } catch (Exception e) {
            logger.warn("Failed to capture element screenshot for selector '{}', falling back to viewport: {}", selector, e.getMessage());
            return captureViewportScreenshot(driver, config);
        }
    }
    
    /**
     * Capture viewport screenshot
     */
    private static byte[] captureViewportScreenshot(WebDriver driver, ScreenshotConfig config) {
        return ((TakesScreenshot) driver).getScreenshotAs(OutputType.BYTES);
    }
    
    /**
     * Hide elements on the page
     */
    private static void hideElements(WebDriver driver, List<String> selectors) {
        if (selectors.isEmpty()) return;
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        for (String selector : selectors) {
            try {
                js.executeScript(
                    "document.querySelectorAll(arguments[0]).forEach(el => el.style.visibility = 'hidden');",
                    selector
                );
            } catch (Exception e) {
                logger.warn("Failed to hide elements with selector '{}': {}", selector, e.getMessage());
            }
        }
    }
    
    /**
     * Show previously hidden elements
     */
    private static void showElements(WebDriver driver, List<String> selectors) {
        if (selectors.isEmpty()) return;
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        for (String selector : selectors) {
            try {
                js.executeScript(
                    "document.querySelectorAll(arguments[0]).forEach(el => el.style.visibility = 'visible');",
                    selector
                );
            } catch (Exception e) {
                logger.warn("Failed to show elements with selector '{}': {}", selector, e.getMessage());
            }
        }
    }
    
    /**
     * Highlight elements on the page
     */
    private static void highlightElements(WebDriver driver, List<String> selectors) {
        if (selectors.isEmpty()) return;
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        for (String selector : selectors) {
            try {
                js.executeScript(
                    "document.querySelectorAll(arguments[0]).forEach(el => {" +
                    "  el.style.outline = '3px solid #ff0000';" +
                    "  el.style.backgroundColor = 'rgba(255, 255, 0, 0.3)';" +
                    "});",
                    selector
                );
            } catch (Exception e) {
                logger.warn("Failed to highlight elements with selector '{}': {}", selector, e.getMessage());
            }
        }
    }
    
    /**
     * Stitch multiple images together vertically
     */
    private static BufferedImage stitchImages(List<BufferedImage> images, int totalWidth, int totalHeight) {
        BufferedImage result = new BufferedImage(totalWidth, totalHeight, BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = result.createGraphics();
        
        int currentY = 0;
        for (BufferedImage image : images) {
            int height = Math.min(image.getHeight(), totalHeight - currentY);
            graphics.drawImage(image, 0, currentY, totalWidth, currentY + height, 
                             0, 0, image.getWidth(), height, null);
            currentY += height;
            
            if (currentY >= totalHeight) break;
        }
        
        graphics.dispose();
        return result;
    }
    
    /**
     * Resize image while maintaining aspect ratio
     */
    private static BufferedImage resizeImage(BufferedImage original, int maxWidth, int maxHeight) {
        int width = original.getWidth();
        int height = original.getHeight();
        
        // Calculate scaling factor
        double scale = 1.0;
        if (maxWidth > 0 && width > maxWidth) {
            scale = Math.min(scale, (double) maxWidth / width);
        }
        if (maxHeight > 0 && height > maxHeight) {
            scale = Math.min(scale, (double) maxHeight / height);
        }
        
        if (scale >= 1.0) return original; // No resizing needed
        
        int newWidth = (int) (width * scale);
        int newHeight = (int) (height * scale);
        
        BufferedImage resized = new BufferedImage(newWidth, newHeight, original.getType());
        Graphics2D graphics = resized.createGraphics();
        graphics.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
        graphics.drawImage(original, 0, 0, newWidth, newHeight, null);
        graphics.dispose();
        
        return resized;
    }
    
    /**
     * Convert BufferedImage to byte array
     */
    private static byte[] imageToByteArray(BufferedImage image, String format) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, format.toLowerCase(), baos);
        return baos.toByteArray();
    }
    
    /**
     * Add metadata to screenshot
     */
    private static void addMetadata(ScreenshotData screenshot, WebDriver driver, ScreenshotConfig config) {
        try {
            JavascriptExecutor js = (JavascriptExecutor) driver;
            
            // Browser and viewport information
            screenshot.getMetadata().put("user_agent", js.executeScript("return navigator.userAgent"));
            screenshot.getMetadata().put("viewport_width", js.executeScript("return window.innerWidth"));
            screenshot.getMetadata().put("viewport_height", js.executeScript("return window.innerHeight"));
            screenshot.getMetadata().put("page_width", js.executeScript("return document.documentElement.scrollWidth"));
            screenshot.getMetadata().put("page_height", js.executeScript("return document.documentElement.scrollHeight"));
            screenshot.getMetadata().put("scroll_x", js.executeScript("return window.scrollX"));
            screenshot.getMetadata().put("scroll_y", js.executeScript("return window.scrollY"));
            screenshot.getMetadata().put("device_pixel_ratio", js.executeScript("return window.devicePixelRatio"));
            
            // Page information
            screenshot.getMetadata().put("domain", js.executeScript("return window.location.hostname"));
            screenshot.getMetadata().put("protocol", js.executeScript("return window.location.protocol"));
            screenshot.getMetadata().put("path", js.executeScript("return window.location.pathname"));
            
            // Configuration
            screenshot.getMetadata().put("config_full_page", config.isFullPage());
            screenshot.getMetadata().put("config_format", config.getImageFormat());
            screenshot.getMetadata().put("elements_highlighted", config.getElementsToHighlight());
            screenshot.getMetadata().put("elements_hidden", config.getElementsToHide());
            
            // Timestamp and ID
            screenshot.getMetadata().put("capture_time", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            screenshot.getMetadata().put("screenshot_id", screenshot.getId());
            
        } catch (Exception e) {
            logger.warn("Failed to add metadata to screenshot: {}", e.getMessage());
        }
    }
    
    /**
     * Save screenshot to file
     */
    private static void saveScreenshotToFile(ScreenshotData screenshot, ScreenshotConfig config) throws IOException {
        File directory = new File(config.getOutputDirectory());
        if (!directory.exists()) {
            directory.mkdirs();
        }
        
        String filename = generateFilename(screenshot, config);
        File file = new File(directory, filename);
        
        FileUtils.writeByteArrayToFile(file, screenshot.getImageData());
        screenshot.setFilePath(file.getAbsolutePath());
        
        logger.info("Screenshot saved to: {}", file.getAbsolutePath());
    }
    
    /**
     * Compare two screenshots
     */
    public static ImageComparisonResult compareScreenshots(ScreenshotData screenshot1, ScreenshotData screenshot2, double threshold) {
        try {
            BufferedImage img1 = ImageIO.read(new ByteArrayInputStream(screenshot1.getImageData()));
            BufferedImage img2 = ImageIO.read(new ByteArrayInputStream(screenshot2.getImageData()));
            
            return compareImages(img1, img2, threshold);
            
        } catch (IOException e) {
            logger.error("Failed to compare screenshots: {}", e.getMessage(), e);
            throw new ScreenshotException("Image comparison failed", e);
        }
    }
    
    /**
     * Compare two BufferedImages
     */
    public static ImageComparisonResult compareImages(BufferedImage img1, BufferedImage img2, double threshold) {
        ImageComparisonResult result = new ImageComparisonResult();
        result.setThreshold(threshold);
        
        // Ensure images are the same size
        if (img1.getWidth() != img2.getWidth() || img1.getHeight() != img2.getHeight()) {
            // Resize to match smaller dimensions
            int width = Math.min(img1.getWidth(), img2.getWidth());
            int height = Math.min(img1.getHeight(), img2.getHeight());
            img1 = resizeImage(img1, width, height);
            img2 = resizeImage(img2, width, height);
        }
        
        int width = img1.getWidth();
        int height = img1.getHeight();
        int totalPixels = width * height;
        int differentPixels = 0;
        
        // Create diff image
        BufferedImage diffImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        
        // Compare pixel by pixel
        for (int x = 0; x < width; x++) {
            for (int y = 0; y < height; y++) {
                int rgb1 = img1.getRGB(x, y);
                int rgb2 = img2.getRGB(x, y);
                
                if (arePixelsDifferent(rgb1, rgb2)) {
                    differentPixels++;
                    diffImage.setRGB(x, y, Color.RED.getRGB()); // Mark difference in red
                } else {
                    diffImage.setRGB(x, y, rgb1); // Keep original pixel
                }
            }
        }
        
        // Calculate similarity
        double similarity = 1.0 - ((double) differentPixels / totalPixels);
        result.setSimilarity(similarity);
        result.setPassed(similarity >= threshold);
        result.setDiffImage(diffImage);
        
        // Add metrics
        result.getMetrics().put("total_pixels", totalPixels);
        result.getMetrics().put("different_pixels", differentPixels);
        result.getMetrics().put("similarity_percentage", similarity * 100);
        result.getMetrics().put("threshold_percentage", threshold * 100);
        
        // Find difference regions
        result.setDifferences(findDifferenceRegions(diffImage));
        
        return result;
    }
    
    /**
     * Check if two pixels are significantly different
     */
    private static boolean arePixelsDifferent(int rgb1, int rgb2) {
        if (rgb1 == rgb2) return false;
        
        Color c1 = new Color(rgb1);
        Color c2 = new Color(rgb2);
        
        // Calculate color difference using Euclidean distance
        double rDiff = (c1.getRed() - c2.getRed()) / 255.0;
        double gDiff = (c1.getGreen() - c2.getGreen()) / 255.0;
        double bDiff = (c1.getBlue() - c2.getBlue()) / 255.0;
        
        double distance = Math.sqrt(rDiff * rDiff + gDiff * gDiff + bDiff * bDiff);
        
        return distance > PIXEL_TOLERANCE;
    }
    
    /**
     * Find regions of differences in the diff image
     */
    private static List<Rectangle> findDifferenceRegions(BufferedImage diffImage) {
        List<Rectangle> regions = new ArrayList<>();
        boolean[][] visited = new boolean[diffImage.getWidth()][diffImage.getHeight()];
        
        for (int x = 0; x < diffImage.getWidth(); x++) {
            for (int y = 0; y < diffImage.getHeight(); y++) {
                if (!visited[x][y] && diffImage.getRGB(x, y) == Color.RED.getRGB()) {
                    Rectangle region = findConnectedRegion(diffImage, x, y, visited);
                    if (region.width > 5 && region.height > 5) { // Filter small noise
                        regions.add(region);
                    }
                }
            }
        }
        
        return regions;
    }
    
    /**
     * Find connected region of different pixels using flood fill
     */
    private static Rectangle findConnectedRegion(BufferedImage diffImage, int startX, int startY, boolean[][] visited) {
        int minX = startX, maxX = startX;
        int minY = startY, maxY = startY;
        
        Stack<Point> stack = new Stack<>();
        stack.push(new Point(startX, startY));
        
        while (!stack.isEmpty()) {
            Point p = stack.pop();
            int x = p.x, y = p.y;
            
            if (x < 0 || x >= diffImage.getWidth() || y < 0 || y >= diffImage.getHeight() || 
                visited[x][y] || diffImage.getRGB(x, y) != Color.RED.getRGB()) {
                continue;
            }
            
            visited[x][y] = true;
            
            minX = Math.min(minX, x);
            maxX = Math.max(maxX, x);
            minY = Math.min(minY, y);
            maxY = Math.max(maxY, y);
            
            // Add neighbors
            stack.push(new Point(x + 1, y));
            stack.push(new Point(x - 1, y));
            stack.push(new Point(x, y + 1));
            stack.push(new Point(x, y - 1));
        }
        
        return new Rectangle(minX, minY, maxX - minX + 1, maxY - minY + 1);
    }
    
    /**
     * Cache management
     */
    private static void addToCache(ScreenshotData screenshot) {
        if (screenshotCache.size() >= MAX_CACHE_SIZE) {
            // Remove oldest screenshot
            String oldestId = screenshotCache.entrySet().stream()
                .min(Map.Entry.comparingByValue((s1, s2) -> Long.compare(s1.getTimestamp(), s2.getTimestamp())))
                .map(Map.Entry::getKey)
                .orElse(null);
            
            if (oldestId != null) {
                screenshotCache.remove(oldestId);
            }
        }
        
        screenshotCache.put(screenshot.getId(), screenshot);
    }
    
    /**
     * Utility methods
     */
    private static String generateScreenshotId() {
        return "screenshot-" + System.currentTimeMillis() + "-" + 
               UUID.randomUUID().toString().substring(0, 8);
    }
    
    private static String generateFilename(ScreenshotData screenshot, ScreenshotConfig config) {
        LocalDateTime now = LocalDateTime.now();
        String timestamp = now.format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        
        String domain = "";
        try {
            domain = (String) screenshot.getMetadata().get("domain");
            if (domain != null) {
                domain = domain.replaceAll("[^a-zA-Z0-9]", "_") + "_";
            } else {
                domain = "";
            }
        } catch (Exception e) {
            domain = "";
        }
        
        return String.format("%s%s_%s.%s", 
            domain, timestamp, screenshot.getId(), config.getImageFormat().toLowerCase());
    }
    
    /**
     * Get screenshot from cache
     */
    public static ScreenshotData getScreenshotFromCache(String screenshotId) {
        return screenshotCache.get(screenshotId);
    }
    
    /**
     * Get all cached screenshots
     */
    public static Map<String, ScreenshotData> getAllCachedScreenshots() {
        return new HashMap<>(screenshotCache);
    }
    
    /**
     * Clear screenshot cache
     */
    public static void clearCache() {
        screenshotCache.clear();
    }
    
    /**
     * Create default screenshot configuration
     */
    public static ScreenshotConfig createDefaultConfig() {
        return new ScreenshotConfig();
    }
    
    /**
     * Create configuration for full page screenshots
     */
    public static ScreenshotConfig createFullPageConfig() {
        ScreenshotConfig config = new ScreenshotConfig();
        config.setFullPage(true);
        config.setImageFormat("PNG");
        return config;
    }
    
    /**
     * Create configuration for element-specific screenshots
     */
    public static ScreenshotConfig createElementConfig(String selector) {
        ScreenshotConfig config = new ScreenshotConfig();
        config.getElementsToHighlight().add(selector);
        config.setCaptureViewportOnly(true);
        return config;
    }
    
    /**
     * Screenshot exception
     */
    public static class ScreenshotException extends RuntimeException {
        public ScreenshotException(String message) {
            super(message);
        }
        
        public ScreenshotException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
