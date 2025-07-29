package com.example.honeypotmanagement.repo;

import com.example.honeypotmanagement.enums.AttackType;
import com.example.honeypotmanagement.enums.Severity;
import com.example.honeypotmanagement.model.AttackEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface AttackEventRepository extends JpaRepository<AttackEvent,Long> {

    // Count queries
    long countByTimestampAfter(LocalDateTime timestamp);

    long countByAttackTypeAndTimestampAfter(AttackType attackType, LocalDateTime timestamp);

    long countBySeverityAndTimestampAfter(Severity severity, LocalDateTime timestamp);

    long countByTimestampBetween(LocalDateTime start, LocalDateTime end);

    // Find queries
    Page<AttackEvent> findByAttackType(AttackType attackType, Pageable pageable);

    Page<AttackEvent> findBySeverity(Severity severity, Pageable pageable);

    Page<AttackEvent> findByAttackTypeAndSeverity(AttackType attackType,
                                                  Severity severity,
                                                  Pageable pageable);

    Optional<AttackEvent> findTopByOrderByTimestampDesc();

    // Custom queries for analytics
    @Query("SELECT a.sourceIp, COUNT(a) as attackCount " +
            "FROM AttackEvent a " +
            "WHERE a.timestamp > :since " +
            "GROUP BY a.sourceIp " +
            "ORDER BY attackCount DESC")
    List<Object[]> findTopAttackingIPs(@Param("since") LocalDateTime since);

    @Query("SELECT a.country, COUNT(a) as attackCount " +
            "FROM AttackEvent a " +
            "WHERE a.timestamp > :since AND a.country IS NOT NULL " +
            "GROUP BY a.country " +
            "ORDER BY attackCount DESC")
    List<Object[]> getAttacksByCountry(@Param("since") LocalDateTime since);


    //Todo Order By for below two methods
    @Query("SELECT HOUR(a.timestamp) as hour, COUNT(a) as attackCount " +
            "FROM AttackEvent a " +
            "WHERE a.timestamp > :since " +
            "GROUP BY HOUR(a.timestamp) " +
            "ORDER BY HOUR(a.timestamp)\n")
    List<Object[]> getAttacksByHour(@Param("since") LocalDateTime since);

    @Query("SELECT HOUR(a.timestamp) as hour, COUNT(a) as attackCount " +
            "FROM AttackEvent a " +
            "WHERE a.timestamp > :since AND a.attackType = :attackType " +
            "GROUP BY HOUR(a.timestamp) " +
            "ORDER BY HOUR(a.timestamp)\n ")
    List<Object[]> getAttacksByTypeAndHour(@Param("attackType") AttackType attackType,
                                           @Param("since") LocalDateTime since);

    @Query("SELECT a.targetEndpoint, COUNT(a) as attackCount " +
            "FROM AttackEvent a " +
            "WHERE a.timestamp > :since " +
            "GROUP BY a.targetEndpoint " +
            "ORDER BY attackCount DESC")
    List<Object[]> getMostTargetedEndpoints(@Param("since") LocalDateTime since);

    @Query("SELECT a.payload, COUNT(a) as frequency " +
            "FROM AttackEvent a " +
            "WHERE a.timestamp > :since " +
            "GROUP BY a.payload " +
            "HAVING COUNT(a) > 1 " +
            "ORDER BY frequency DESC")
    List<Object[]> getCommonAttackPatterns(@Param("since") LocalDateTime since);

    @Query("SELECT a.userAgent, COUNT(a) as frequency " +
            "FROM AttackEvent a " +
            "WHERE a.timestamp > :since AND a.userAgent IS NOT NULL " +
            "GROUP BY a.userAgent " +
            "ORDER BY frequency DESC")
    List<Object[]> getTopUserAgents(@Param("since") LocalDateTime since);

    @Modifying
    @Transactional
    @Query("UPDATE AttackEvent a SET a.blocked = true WHERE a.sourceIp = :ipAddress")
    void markIPAsBlocked(@Param("ipAddress") String ipAddress);

    // Find attacks by IP and time range
    List<AttackEvent> findBySourceIpAndTimestampBetween(String sourceIp,
                                                        LocalDateTime start,
                                                        LocalDateTime end);

    // Find recent attacks by severity
    @Query("SELECT a FROM AttackEvent a " +
            "WHERE a.severity = :severity " +
            "ORDER BY a.timestamp DESC")
    List<AttackEvent> findRecentBySeverity(@Param("severity") Severity severity,
                                           Pageable pageable);
}
