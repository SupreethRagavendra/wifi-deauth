package com.wifi.security.service;

import com.wifi.security.entity.Institute;
import com.wifi.security.enums.InstituteType;
import com.wifi.security.exception.ResourceNotFoundException;
import com.wifi.security.repository.InstituteRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Service for Institute-related operations.
 */
@Service
public class InstituteService {

    private static final Logger logger = LoggerFactory.getLogger(InstituteService.class);

    private final InstituteRepository instituteRepository;

    public InstituteService(InstituteRepository instituteRepository) {
        this.instituteRepository = instituteRepository;
    }

    /**
     * Get an institute by its unique code.
     * 
     * @param code The institute code
     * @return The institute
     * @throws ResourceNotFoundException if not found
     */
    @Transactional(readOnly = true)
    public Institute getInstituteByCode(String code) {
        return instituteRepository.findByInstituteCode(code)
                .orElseThrow(() -> new ResourceNotFoundException("Institute", code));
    }

    /**
     * Get an institute by ID.
     * 
     * @param id The institute ID
     * @return The institute
     * @throws ResourceNotFoundException if not found
     */
    @Transactional(readOnly = true)
    public Institute getInstituteById(String id) {
        return instituteRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Institute", id));
    }

    /**
     * Find an institute by code (optional).
     * 
     * @param code The institute code
     * @return Optional containing the institute if found
     */
    @Transactional(readOnly = true)
    public Optional<Institute> findByCode(String code) {
        return instituteRepository.findByInstituteCode(code);
    }

    /**
     * Check if an institute code exists.
     * 
     * @param code The institute code
     * @return true if exists
     */
    @Transactional(readOnly = true)
    public boolean existsByCode(String code) {
        return instituteRepository.existsByInstituteCode(code);
    }

    /**
     * Get all institutes.
     * 
     * @return List of all institutes
     */
    @Transactional(readOnly = true)
    public List<Institute> getAllInstitutes() {
        return instituteRepository.findAll();
    }

    /**
     * Save an institute.
     * 
     * @param institute The institute to save
     * @return The saved institute
     */
    @Transactional
    public Institute save(Institute institute) {
        logger.info("Saving institute: {}", institute.getInstituteName());
        return instituteRepository.save(institute);
    }
}
