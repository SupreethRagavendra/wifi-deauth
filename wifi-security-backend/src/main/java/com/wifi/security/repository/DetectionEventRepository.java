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
}
