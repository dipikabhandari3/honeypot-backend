package com.example.honeypotmanagement.service;

import com.example.honeypotmanagement.enums.AttackType;
import com.example.honeypotmanagement.model.AttackEvent;
import com.example.honeypotmanagement.repo.AttackEventRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
@Slf4j
public class AttackDetectionService {

    private final AttackEventRepository attackEventRepository;
    private final SimpMessagingTemplate messagingTemplate;

    private final Map<String, Integer> bruteForceAttempts = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> lastAttemptTime = new ConcurrentHashMap<>();

    // SQL Injection patterns
    private final Pattern[] sqlInjectionPatterns = {
            Pattern.compile("('|(\\-\\-)|(;)|(\\|)|(\\*)|(%))", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(union|select|insert|delete|update|drop|create|exec|execute)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(script|javascript|vbscript|onload|onerror)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(\\<|%3C).*script.*(\\>|%3E)", Pattern.CASE_INSENSITIVE)
    };

    // XSS patterns
    private final Pattern[] xssPatterns = {
            Pattern.compile("<script[^>]*>.*?</script>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),
            Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("on\\w+\\s*=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<iframe[^>]*>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("eval\\s*\\(", Pattern.CASE_INSENSITIVE)
    };

    // Command injection patterns
    private final Pattern[] commandInjectionPatterns = {
            Pattern.compile("(;|\\||&|`|\\$\\(|\\$\\{)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(cat|ls|pwd|whoami|id|uname|ps|netstat)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(wget|curl|nc|ncat|telnet|ssh)", Pattern.CASE_INSENSITIVE)
    };

    // Directory traversal patterns
    private final Pattern[] directoryTraversalPatterns = {
            Pattern.compile("(\\.\\./|\\.\\.\\\\/)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(%2e%2e%2f|%2e%2e%5c)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(etc/passwd|windows/system32)", Pattern.CASE_INSENSITIVE)
    };


    public boolean detectSqlInjection(HttpServletRequest request) {
        String queryString = request.getQueryString();
        System.out.println("Query String: " + queryString);
        String requestUri = request.getRequestURI();

        if (queryString != null) {
            for (Pattern pattern : sqlInjectionPatterns) {
                if (pattern.matcher(queryString).find()) {
                    log.warn("SQL Injection detected from {}: {}", request.getRemoteAddr(), queryString);
                    return true;
                }
            }
        }

        for (Pattern pattern : sqlInjectionPatterns) {
            if (pattern.matcher(requestUri).find()) {
                log.warn("SQL Injection in URI from {}: {}", request.getRemoteAddr(), requestUri);
                return true;
            }
        }

        return false;
    }

    public boolean detectBruteForce(String ip, String username) {
        String key = ip + ":" + username;
        LocalDateTime now = LocalDateTime.now();

        // Reset counter if more than 5 minutes have passed
        LocalDateTime lastAttempt = lastAttemptTime.get(key);
        if (lastAttempt != null && lastAttempt.isBefore(now.minusMinutes(5))) {
            bruteForceAttempts.remove(key);
        }

        int attempts = bruteForceAttempts.getOrDefault(key, 0) + 1;
        bruteForceAttempts.put(key, attempts);
        lastAttemptTime.put(key, now);

        if (attempts > 3) {
            log.warn("Brute force attack detected from {} for user {}", ip, username);
            return true;
        }

        return false;
    }

    public boolean detectXSS(String input) {
        if (input == null) return false;

        for (Pattern pattern : xssPatterns) {
            if (pattern.matcher(input).find()) {
                log.warn("XSS attack detected: {}", input);
                return true;
            }
        }
        return false;
    }

    public boolean detectCommandInjection(String input) {
        if (input == null) return false;

        for (Pattern pattern : commandInjectionPatterns) {
            if (pattern.matcher(input).find()) {
                log.warn("Command injection detected: {}", input);
                return true;
            }
        }
        return false;
    }

    public boolean detectDirectoryTraversal(String input) {
        if (input == null) return false;

        for (Pattern pattern : directoryTraversalPatterns) {
            if (pattern.matcher(input).find()) {
                log.warn("Directory traversal detected: {}", input);
                return true;
            }
        }
        return false;
    }

    public boolean detectMaliciousFile(String fileName) {
        if (fileName == null) return false;

        String[] maliciousExtensions = {".exe", ".bat", ".cmd", ".scr", ".vbs", ".js", ".php", ".jsp"};
        String lowerFileName = fileName.toLowerCase();

        for (String ext : maliciousExtensions) {
            if (lowerFileName.endsWith(ext)) {
                log.warn("Malicious file upload attempt: {}", fileName);
                return true;
            }
        }

        return false;
    }

    public Map<String, Object> getAttackStatistics() {
        Map<String, Object> stats = new HashMap<>();

        // Total attacks today
        LocalDateTime startOfDay = LocalDateTime.now().withHour(0).withMinute(0).withSecond(0);
        long todayAttacks = attackEventRepository.countByTimestampAfter(startOfDay);

        // Attacks by type
        Map<String, Long> attacksByType = new HashMap<>();
        for (AttackType type : AttackType.values()) {
            long count = attackEventRepository.countByAttackTypeAndTimestampAfter(type, startOfDay);
            attacksByType.put(type.toString(), count);
        }

        // Top attacking IPs
        var topIps = attackEventRepository.findTopAttackingIPs(java.time.LocalDateTime.now().minusDays(1));

        stats.put("todayAttacks", todayAttacks);
        stats.put("attacksByType", attacksByType);
        stats.put("topAttackingIPs", topIps);
        stats.put("activeBruteForceAttempts", bruteForceAttempts.size());

        return stats;
    }

    public void recordAttack(AttackEvent event) {
        attackEventRepository.save(event);

        // Send real-time notification to frontend
        Map<String, Object> notification = new HashMap<>();
        notification.put("id", event.getId());
        notification.put("type", event.getAttackType().toString());
        notification.put("sourceIp", event.getSourceIp());
        notification.put("severity", event.getSeverity().toString());
        notification.put("timestamp", event.getTimestamp().toString());
        notification.put("details", event.getPayload());
        notification.put("endpoint", event.getTargetEndpoint());
        notification.put("userAgent", event.getUserAgent());
        notification.put("geolocation", event.getGeolocation());

        // Send to WebSocket
        messagingTemplate.convertAndSend("/topic/attacks", notification);

        log.info("Attack recorded: {} from {} - {}",
                event.getAttackType(), event.getSourceIp(), event.getPayload());
    }


}
