package com.wifi.security.repository;

import com.wifi.security.entity.DetectedAnomaly;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.wifi.security.entity.Institute;

import java.util.List;

@Repository
public interface DetectedAnomalyRepository extends JpaRepository<DetectedAnomaly, String> {
    List<DetectedAnomaly> findByInstituteOrderByDetectedAtDesc(Institute institute);

    List<DetectedAnomaly> findTop20ByOrderByDetectedAtDesc();
}
