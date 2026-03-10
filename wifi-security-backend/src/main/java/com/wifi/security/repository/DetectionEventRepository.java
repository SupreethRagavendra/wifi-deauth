package com.wifi.security.repository;

import com.wifi.security.entity.detection.DetectionEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface DetectionEventRepository extends JpaRepository<DetectionEvent, Long> {
        List<DetectionEvent> findTop20ByOrderByDetectedAtDesc();

        List<DetectionEvent> findTop100ByOrderByDetectedAtDesc();

        List<DetectionEvent> findByDetectedAtAfter(LocalDateTime cutoff);

        List<DetectionEvent> findByDetectedAtAfterOrderByDetectedAtDesc(LocalDateTime cutoff);

        // Institute-scoped queries (multi-tenant support)
        List<DetectionEvent> findByInstituteIdAndDetectedAtAfter(String instituteId, LocalDateTime cutoff);

        List<DetectionEvent> findByInstituteIdAndDetectedAtAfterOrderByDetectedAtDesc(String instituteId,
                        LocalDateTime cutoff);

        List<DetectionEvent> findTop20ByInstituteIdOrderByDetectedAtDesc(String instituteId);

        List<DetectionEvent> findTop20ByInstituteIdAndTargetBssidInOrderByDetectedAtDesc(String instituteId,
                        List<String> targetBssids);

        long countByInstituteIdAndDetectedAtAfter(String instituteId, LocalDateTime cutoff);

        // MAC-based filtering for multi-faculty support (Issue 6)
        List<DetectionEvent> findTop50ByTargetMacInOrderByDetectedAtDesc(List<String> targetMacs);

        List<DetectionEvent> findTop50ByInstituteIdAndTargetMacInOrderByDetectedAtDesc(String instituteId,
                        List<String> targetMacs);

        // Forensic service: get recent events for an institute
        List<DetectionEvent> findTop50ByInstituteIdOrderByDetectedAtDesc(String instituteId);

        List<DetectionEvent> findTop50ByOrderByDetectedAtDesc();
}
