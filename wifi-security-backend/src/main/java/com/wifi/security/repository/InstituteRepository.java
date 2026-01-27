package com.wifi.security.repository;

import com.wifi.security.entity.Institute;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository for Institute entity operations.
 */
@Repository
public interface InstituteRepository extends JpaRepository<Institute, String> {

    /**
     * Find an institute by its unique code.
     */
    Optional<Institute> findByInstituteCode(String instituteCode);

    /**
     * Check if an institute code already exists.
     */
    boolean existsByInstituteCode(String instituteCode);
}
