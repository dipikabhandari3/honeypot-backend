package com.example.honeypotmanagement.controller;

import com.example.honeypotmanagement.enums.AttackType;
import com.example.honeypotmanagement.enums.Severity;
import com.example.honeypotmanagement.model.AttackEvent;
import com.example.honeypotmanagement.service.AttackDetectionService;
import com.example.honeypotmanagement.service.GeoLocationService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/honeypot")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "http://localhost:4200")
public class HoneyPotController {

    private final AttackDetectionService attackDetectionService;
    private final GeoLocationService geoLocationService;

    //Simulate existing blog endpoints
    @GetMapping("/getAllBlogs")
    public ResponseEntity<?> getAllBlogs(HttpServletRequest request) {
        log.info("Blog access attempt from: {} ", request.getRemoteAddr());

        //Check for suspicious patterns
        if(attackDetectionService.detectSqlInjection(request)){
            recordAttack(request, AttackType.SQL_INJECTION,"SQL injection in getAllBlogs");
            return ResponseEntity.badRequest().body("Invalid Request");

        }

        return ResponseEntity.ok(generateFakeBlogData());
    }


    private boolean containsSqlInjectionPattern(String input) {
        if (input == null) return false;

        String normalized = input.toLowerCase();
        String[] patterns = {
                "' or '1'='1", "' or 1=1", "union select", "drop table",
                "admin'--", "'--", "'; drop", " or ", " and "
        };

        for (String pattern : patterns) {
            if (normalized.contains(pattern)) {
                log.info("🔥 SQL injection pattern '{}' found in: '{}'", pattern, input);
                return true;
            }
        }
        return false;
    }


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials,
                                   HttpServletRequest request) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        log.info("Login attempt - Username: {}, IP: {}", username, request.getRemoteAddr());

        // Detect brute force attempts
        if (attackDetectionService.detectBruteForce(request.getRemoteAddr(), username)) {
            recordAttack(request, AttackType.BRUTE_FORCE_LOGIN,
                    "Brute force login attempt: " + username);
        }

        // Always return authentication failure but make it believable
        if (isCommonAttackCredential(username, password)) {
            recordAttack(request, AttackType.UNAUTHORIZED_ACCESS,
                    "Common attack credentials used");
        }

        return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
    }

    private boolean isCommonAttackCredential(String username, String password) {
        String[] commonUsernames = {"admin", "root", "administrator", "test", "guest"};
        String[] commonPasswords = {"password", "123456", "admin", "root", "test"};

        for (String user : commonUsernames) {
            if (user.equalsIgnoreCase(username)) return true;
        }
        for (String pass : commonPasswords) {
            if (pass.equals(password)) return true;
        }
        return false;
    }

    @PostMapping("/posts")
    public ResponseEntity<?> createPost(@RequestBody Map<String, Object> post,
                                        HttpServletRequest request) {
        String content = (String) post.get("content");

        // Check for XSS attempts
        if (attackDetectionService.detectXSS(content)) {
            recordAttack(request, AttackType.XSS_ATTACK, "XSS in post content: " + content);
            return ResponseEntity.badRequest().body("Invalid content");
        }

        // Check for command injection
        if (attackDetectionService.detectCommandInjection(content)) {
            recordAttack(request, AttackType.COMMAND_INJECTION,
                    "Command injection attempt: " + content);
            return ResponseEntity.badRequest().body("Invalid content");
        }

        // Record safe post as informational (optional)
        recordAttack(request, AttackType.INFORMATIONAL, "Safe post submitted");

        return ResponseEntity.ok(Map.of("message", "Post created", "id", System.currentTimeMillis()));
    }

    @GetMapping("/posts/{id}")
    public ResponseEntity<?> getPost(@PathVariable String id, HttpServletRequest request) {
        // Check for directory traversal
        if (attackDetectionService.detectDirectoryTraversal(id)) {
            recordAttack(request, AttackType.DIRECTORY_TRAVERSAL,
                    "Directory traversal attempt: " + id);
            return ResponseEntity.badRequest().body("Invalid post ID");
        }

        return ResponseEntity.ok(generateFakePost(id));
    }

    @PostMapping("/upload")
    public ResponseEntity<?> uploadFile(@RequestParam("file") String fileName,
                                        HttpServletRequest request) {
        // Check for malware upload attempts
        if (attackDetectionService.detectMaliciousFile(fileName)) {
            recordAttack(request, AttackType.MALWARE_UPLOAD,
                    "Malicious file upload: " + fileName);
            return ResponseEntity.badRequest().body("File type not allowed");
        }

        return ResponseEntity.ok(Map.of("message", "File uploaded", "filename", fileName));
    }

    // Honeypot-specific endpoints to attract attackers
    @GetMapping("/admin")
    public ResponseEntity<?> adminPanel(HttpServletRequest request) {
        recordAttack(request, AttackType.UNAUTHORIZED_ACCESS,
                "Admin panel access attempt");
        return ResponseEntity.status(403).body("Access denied");
    }

    @GetMapping("/config.php")
    public ResponseEntity<?> configFile(HttpServletRequest request) {
        recordAttack(request, AttackType.UNAUTHORIZED_ACCESS,
                "Config file access attempt");
        return ResponseEntity.notFound().build();
    }

    @GetMapping("/wp-admin/**")
    public ResponseEntity<?> wordpressAdmin(HttpServletRequest request) {
        recordAttack(request, AttackType.UNAUTHORIZED_ACCESS,
                "WordPress admin access attempt");
        return ResponseEntity.notFound().build();
    }

    private Map<String, Object> generateFakePost(String id) {
        return Map.of(
                "id", id,
                "title", "Sample Post " + id,
                "content", "This is content for post " + id,
                "author", "System",
                "created", System.currentTimeMillis()
        );
    }



    private void recordAttack(HttpServletRequest request, AttackType type, String details){
        AttackEvent event = new AttackEvent();
        event.setAttackType(type);
        event.setSourceIp(request.getRemoteAddr());
        event.setTargetEndpoint(request.getRequestURI());
        event.setUserAgent(request.getHeader("User-Agent"));
        event.setPayload(details);
        event.setSeverity(determineSeverity(type));
        event.setGeolocation(geoLocationService.getLocation(request.getRemoteAddr()));

        attackDetectionService.recordAttack(event);
    }

    private Severity determineSeverity(AttackType type){
        return switch (type){
            case SQL_INJECTION, COMMAND_INJECTION, MALWARE_UPLOAD -> Severity.CRITICAL;
            case XSS_ATTACK,DIRECTORY_TRAVERSAL -> Severity.HIGH;
            case BRUTE_FORCE_LOGIN,UNAUTHORIZED_ACCESS -> Severity.MEDIUM;
            default -> Severity.LOW;

        };
    }

    private Map<String, Object> generateFakeBlogData() {
        return
                Map.of
                        ("blogs",
                                List.of(
                                        Map.of("id", 1, "title", "Welcome to our blog", "content", "This is a sample post"),
                                        Map.of("id", 2, "title", "Security Best Practices", "content", "Learn about security...")
                                ),
                                "total", 2
                        );
    }

}
