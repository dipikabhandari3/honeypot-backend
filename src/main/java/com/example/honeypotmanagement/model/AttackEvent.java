package com.example.honeypotmanagement.model;

import com.example.honeypotmanagement.enums.AttackType;
import com.example.honeypotmanagement.enums.Severity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "attack_events")
public class AttackEvent {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "attack_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private AttackType attackType;

    @Column(name = "source_ip", nullable = false)
    private String sourceIp;

    @Column(name = "target_endpoint")
    private String targetEndpoint;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "payload", columnDefinition = "TEXT")
    private String payload;

    @Column(name = "severity")
    @Enumerated(EnumType.STRING)
    private Severity severity;

    @Column(name = "blocked")
    private boolean blocked = false;

    @Column(name = "country")
    private String country;

    @Column(name = "geolocation")
    private String geolocation;

    @Column(name = "timestamp", nullable = false)
    private LocalDateTime timestamp;

    @Column(name = "session_id")
    private String sessionId;

    @Column(name = "attack_details", columnDefinition = "TEXT")
    private String attackDetails;

    @PrePersist
    protected void onCreate() {
        timestamp = LocalDateTime.now();
    }
}
