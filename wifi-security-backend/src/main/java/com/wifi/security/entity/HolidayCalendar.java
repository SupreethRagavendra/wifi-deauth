package com.wifi.security.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * Entity representing holidays for time anomaly detection adjustment.
 * 
 * <p>
 * During holidays, unusual activity patterns are expected, so the
 * time anomaly score is reduced by the configured modifier.
 * </p>
 * 
 * @author Algorithm Design Specialist
 * @since 2026-02-07
 */
@Entity
@Table(name = "holiday_calendar", indexes = {
        @Index(name = "idx_holiday_date", columnList = "holiday_date"),
        @Index(name = "idx_holiday_institute", columnList = "institute_id, holiday_date")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class HolidayCalendar {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "holiday_id")
    private Integer id;

    /**
     * Date of the holiday.
     */
    @Column(name = "holiday_date", nullable = false)
    private LocalDate holidayDate;

    /**
     * Human-readable name of the holiday.
     */
    @Column(name = "holiday_name", nullable = false, length = 100)
    private String holidayName;

    /**
     * Optional institute ID for organization-specific holidays.
     * NULL means the holiday applies globally.
     */
    @Column(name = "institute_id", length = 36)
    private String instituteId;

    /**
     * Score modifier to apply on this holiday.
     * Default: 0.70 (30% reduction in time anomaly score)
     */
    @Column(name = "score_modifier", nullable = false, precision = 3, scale = 2)
    private BigDecimal scoreModifier = BigDecimal.valueOf(0.70);

    /**
     * Whether this holiday recurs annually (e.g., Christmas, Independence Day).
     */
    @Column(name = "is_annual", nullable = false)
    private Boolean isAnnual = false;

    /**
     * Timestamp when this holiday was added.
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
    }
}
