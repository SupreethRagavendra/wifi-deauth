package com.wifi.security.repository;

import com.wifi.security.entity.HolidayCalendar;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

/**
 * Repository for holiday calendar entries.
 * 
 * <p>
 * Used to check if a given date is a holiday for adjusting
 * time anomaly detection scores.
 * </p>
 * 
 * @author Algorithm Design Specialist
 * @since 2026-02-07
 */
@Repository
public interface HolidayCalendarRepository extends JpaRepository<HolidayCalendar, Integer> {

    /**
     * Checks if a specific date is a holiday.
     * Considers both global holidays and annual recurrences.
     * 
     * @param date Date to check
     * @return true if the date is a holiday
     */
    @Query("""
            SELECT COUNT(h) > 0
            FROM HolidayCalendar h
            WHERE h.holidayDate = :date
               OR (h.isAnnual = true
                   AND FUNCTION('MONTH', h.holidayDate) = FUNCTION('MONTH', :date)
                   AND FUNCTION('DAY', h.holidayDate) = FUNCTION('DAY', :date))
            """)
    boolean existsByHolidayDate(@Param("date") LocalDate date);

    /**
     * Checks if a specific date is a holiday for a specific institute.
     * Includes both global holidays and institute-specific holidays.
     * 
     * @param date        Date to check
     * @param instituteId Institute ID
     * @return true if the date is a holiday for this institute
     */
    @Query("""
            SELECT COUNT(h) > 0
            FROM HolidayCalendar h
            WHERE (h.holidayDate = :date
                   OR (h.isAnnual = true
                       AND FUNCTION('MONTH', h.holidayDate) = FUNCTION('MONTH', :date)
                       AND FUNCTION('DAY', h.holidayDate) = FUNCTION('DAY', :date)))
              AND (h.instituteId IS NULL OR h.instituteId = :instituteId)
            """)
    boolean existsByHolidayDateAndInstituteId(
            @Param("date") LocalDate date,
            @Param("instituteId") String instituteId);

    /**
     * Finds holiday entry for a specific date (if exists).
     * 
     * @param date Date to look up
     * @return Optional holiday entry
     */
    Optional<HolidayCalendar> findByHolidayDate(LocalDate date);

    /**
     * Finds all holidays for a specific institute (including global ones).
     * 
     * @param instituteId Institute ID
     * @return List of applicable holidays
     */
    @Query("""
            SELECT h FROM HolidayCalendar h
            WHERE h.instituteId IS NULL OR h.instituteId = :instituteId
            ORDER BY h.holidayDate ASC
            """)
    List<HolidayCalendar> findByInstituteIdIncludingGlobal(@Param("instituteId") String instituteId);

    /**
     * Finds holidays within a date range.
     * 
     * @param startDate Range start
     * @param endDate   Range end
     * @return List of holidays in range
     */
    List<HolidayCalendar> findByHolidayDateBetween(LocalDate startDate, LocalDate endDate);

    /**
     * Finds all global holidays (instituteId is null).
     * 
     * @return List of global holidays
     */
    List<HolidayCalendar> findByInstituteIdIsNull();

    /**
     * Finds all annual recurring holidays.
     * 
     * @return List of annual holidays
     */
    List<HolidayCalendar> findByIsAnnualTrue();

    /**
     * Gets the score modifier for a specific date.
     * Returns 1.0 (no modification) if not a holiday.
     * 
     * @param date Date to check
     * @return Score modifier (default 0.7 for holidays, 1.0 otherwise)
     */
    @Query("""
            SELECT COALESCE(h.scoreModifier, 1.0)
            FROM HolidayCalendar h
            WHERE h.holidayDate = :date
            """)
    Optional<Double> getScoreModifierForDate(@Param("date") LocalDate date);
}
