package com.wifi.security.repository;

import com.wifi.security.entity.ScanResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.wifi.security.entity.Institute;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface ScanResultRepository extends JpaRepository<ScanResult, String> {
    List<ScanResult> findByInstituteOrderByScannedAtDesc(Institute institute);

    List<ScanResult> findByInstituteAndScannedAtAfter(Institute institute, LocalDateTime timestamp);
}
