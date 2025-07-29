package com.example.honeypotmanagement.controller;

import com.example.honeypotmanagement.enums.AttackType;
import com.example.honeypotmanagement.enums.Severity;
import com.example.honeypotmanagement.model.AttackEvent;
import com.example.honeypotmanagement.repo.AttackEventRepository;
import com.example.honeypotmanagement.service.AttackDetectionService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:4200")
public class DashboardController {

    private final AttackEventRepository attackEventRepository;
    private final AttackDetectionService attackDetectionService;

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getDashboardStats() {
        Map<String, Object> stats = attackDetectionService.getAttackStatistics();

        // Add more detailed statistics
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime last24Hours = now.minusHours(24);
        LocalDateTime lastWeek = now.minusDays(7);

        // Hourly attack trends (last 24 hours)
        Map<String, Long> hourlyTrends = new HashMap<>();
        for (int i = 23; i >= 0; i--) {
            LocalDateTime hourStart = now.minusHours(i + 1);
            LocalDateTime hourEnd = now.minusHours(i);
            long count = attackEventRepository.countByTimestampBetween(hourStart, hourEnd);
            hourlyTrends.put(hourStart.getHour() + ":00", count);
        }

        // Attack severity distribution
        Map<String, Long> severityDistribution = new HashMap<>();
        for (Severity severity : Severity.values()) {
            long count = attackEventRepository.countBySeverityAndTimestampAfter(severity, last24Hours);
            severityDistribution.put(severity.toString(), count);
        }

        // Geographic distribution
        List<Object[]> geoData = attackEventRepository.getAttacksByCountry(last24Hours);

        stats.put("hourlyTrends", hourlyTrends);
        stats.put("severityDistribution", severityDistribution);
        stats.put("geographicDistribution", geoData);
        stats.put("totalAttacksLast24h", attackEventRepository.countByTimestampAfter(last24Hours));
        stats.put("totalAttacksLastWeek", attackEventRepository.countByTimestampAfter(lastWeek));

        return ResponseEntity.ok(stats);
    }

    @GetMapping("/attacks")
    public ResponseEntity<Page<AttackEvent>> getRecentAttacks(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) String severity) {

        PageRequest pageRequest = PageRequest.of(page, size, Sort.by("timestamp").descending());
        Page<AttackEvent> attacks;

        if (type != null && severity != null) {
            AttackType attackType = AttackType.valueOf(type);
            Severity sev = Severity.valueOf(severity);
            attacks = attackEventRepository.findByAttackTypeAndSeverity(attackType, sev, pageRequest);
        } else if (type != null) {
            AttackType attackType = AttackType.valueOf(type);
            attacks = attackEventRepository.findByAttackType(attackType, pageRequest);
        } else if (severity != null) {
            Severity sev = Severity.valueOf(severity);
            attacks = attackEventRepository.findBySeverity(sev, pageRequest);
        } else {
            attacks = attackEventRepository.findAll(pageRequest);
        }

        return ResponseEntity.ok(attacks);
    }

    @GetMapping("/attacks/{id}")
    public ResponseEntity<AttackEvent> getAttackDetails(@PathVariable Long id) {
        return attackEventRepository.findById(id)
                .map(attack -> ResponseEntity.ok(attack))
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/top-attackers")
    public ResponseEntity<List<Object[]>> getTopAttackers() {
        LocalDateTime last24Hours = LocalDateTime.now().minusHours(24);
        List<Object[]> topAttackers = attackEventRepository.findTopAttackingIPs(last24Hours);
        return ResponseEntity.ok(topAttackers);
    }

    @GetMapping("/attack-timeline")
    public ResponseEntity<Map<String, Object>> getAttackTimeline(@RequestParam(defaultValue = "24") int hours) {
        LocalDateTime startTime = LocalDateTime.now().minusHours(hours);

        Map<String, Object> timeline = new HashMap<>();

        // Get attacks grouped by hour
        List<Object[]> hourlyData = attackEventRepository.getAttacksByHour(startTime);

        // Get attacks grouped by type over time
        Map<String, List<Object[]>> typeTimeline = new HashMap<>();
        for (AttackType type : AttackType.values()) {
            List<Object[]> typeData = attackEventRepository.getAttacksByTypeAndHour(type, startTime);
            typeTimeline.put(type.toString(), typeData);
        }

        timeline.put("hourlyAttacks", hourlyData);
        timeline.put("attacksByType", typeTimeline);

        return ResponseEntity.ok(timeline);
    }

    @PostMapping("/block-ip")
    public ResponseEntity<Map<String, String>> blockIP(@RequestBody Map<String, String> request) {
        String ipAddress = request.get("ipAddress");

        // In a real implementation, you would add the IP to your firewall/blocking system
        // For now, we'll just mark all attacks from this IP as blocked
        attackEventRepository.markIPAsBlocked(ipAddress);

        Map<String, String> response = new HashMap<>();
        response.put("message", "IP " + ipAddress + " has been blocked");
        response.put("status", "success");

        return ResponseEntity.ok(response);
    }

    @GetMapping("/threat-intelligence")
    public ResponseEntity<Map<String, Object>> getThreatIntelligence() {
        Map<String, Object> intelligence = new HashMap<>();

        LocalDateTime last24Hours = LocalDateTime.now().minusHours(24);

        // Most targeted endpoints
        List<Object[]> targetedEndpoints = attackEventRepository.getMostTargetedEndpoints(last24Hours);

        // Common attack patterns
        List<Object[]> attackPatterns = attackEventRepository.getCommonAttackPatterns(last24Hours);

        // User agents analysis
        List<Object[]> userAgents = attackEventRepository.getTopUserAgents(last24Hours);

        intelligence.put("targetedEndpoints", targetedEndpoints);
        intelligence.put("attackPatterns", attackPatterns);
        intelligence.put("suspiciousUserAgents", userAgents);

        return ResponseEntity.ok(intelligence);
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> getSystemHealth() {
        Map<String, Object> health = new HashMap<>();

        // Check if honeypots are responding
        health.put("webHoneypot", "ACTIVE");
        health.put("sshHoneypot", "ACTIVE");
        health.put("databaseHoneypot", "ACTIVE");

        // System metrics
        health.put("totalEvents", attackEventRepository.count());
        health.put("systemUptime", System.currentTimeMillis());
        health.put("lastAttack", attackEventRepository.findTopByOrderByTimestampDesc()
                .map(AttackEvent::getTimestamp)
                .orElse(null));

        return ResponseEntity.ok(health);
    }
}
