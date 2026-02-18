package com.wifi.security.service.layer1;

import com.wifi.security.entity.TimeOfDayBaseline;
import com.wifi.security.repository.TimeOfDayBaselineRepository;
import com.wifi.security.repository.HolidayCalendarRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.*;
import java.time.zone.ZoneOffsetTransition;
import java.time.zone.ZoneRules;
import java.util.Optional;

/**
 * TimeOfDayAnalyzer - Detects deauth attacks at statistically unusual times.
 * 
 * <p>
 * This analyzer complements the existing {@link TimeAnomalyDetector} which
 * focuses
 * on inter-frame timing patterns. This component analyzes hour-of-day and
 * day-of-week
 * patterns against historical baselines.
 * </p>
 * 
 * <h2>Detection Strategy:</h2>
 * <ul>
 * <li>Maintains per-BSSID baselines for each of 168 time slots (7 days × 24
 * hours)</li>
 * <li>Calculates Z-score of current frame rate vs historical baseline</li>
 * <li>Applies context modifiers for holidays, DST, business hours</li>
 * </ul>
 * 
 * <h2>Score Range:</h2>
 * <ul>
 * <li>0 points: Normal (Z &lt; 2.0, within 95% CI)</li>
 * <li>8 points: Unusual (2.0 ≤ Z &lt; 3.0, outside 95% CI)</li>
 * <li>15 points: Anomalous (Z ≥ 3.0, outside 99.7% CI)</li>
 * </ul>
 * 
 * <h2>Statistical Basis:</h2>
 * 
 * <pre>
 * Z-score thresholds based on normal distribution:
 *   P(|Z| &lt; 2.0) = 95.45%  → FPR ≈ 4.55%
 *   P(|Z| &lt; 3.0) = 99.73%  → FPR ≈ 0.27%
 * </pre>
 * 
 * @author Algorithm Design Specialist
 * @version 1.0
 * @since 2026-02-07
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TimeOfDayAnalyzer {

    private final TimeOfDayBaselineRepository baselineRepository;
    private final HolidayCalendarRepository holidayRepository;

    // ========================================================================
    // SCORE CONSTANTS
    // ========================================================================

    /** Score for normal activity (within 95% confidence interval) */
    private static final int SCORE_NORMAL = 0;

    /** Score for unusual activity (outside 95% CI, within 99.7% CI) */
    private static final int SCORE_UNUSUAL = 8;

    /** Score for anomalous activity (outside 99.7% confidence interval) */
    private static final int SCORE_ANOMALOUS = 15;

    // ========================================================================
    // Z-SCORE THRESHOLDS (Statistically justified)
    // ========================================================================

    /**
     * Z-score threshold for normal classification.
     * Values below this are within 95% confidence interval.
     */
    @Value("${detection.layer1.time-of-day.z-threshold-normal:2.0}")
    private double zThresholdNormal;

    /**
     * Z-score threshold for anomalous classification.
     * Values at or above this are outside 99.7% confidence interval.
     */
    @Value("${detection.layer1.time-of-day.z-threshold-anomalous:3.0}")
    private double zThresholdAnomalous;

    // ========================================================================
    // BASELINE PARAMETERS
    // ========================================================================

    /** Minimum samples required for statistical validity (4 weeks of data) */
    private static final int MINIMUM_SAMPLES = 4;

    /**
     * Exponential Moving Average decay factor (effective window ≈ 20 observations)
     */
    private static final double EMA_ALPHA = 0.1;

    /** Default standard deviation for new baselines or zero-variance cases */
    private static final double DEFAULT_STD_DEV = 2.0;

    /** Maximum Z-score cap to prevent numerical overflow */
    private static final double Z_SCORE_CAP = 10.0;

    // ========================================================================
    // CONTEXT MODIFIERS
    // ========================================================================

    /** Score modifier for holidays (30% reduction) */
    @Value("${detection.layer1.time-of-day.holiday-modifier:0.7}")
    private double holidayModifier;

    /** Score modifier for DST transition periods (20% reduction) */
    @Value("${detection.layer1.time-of-day.dst-modifier:0.8}")
    private double dstModifier;

    /** Score boost for weekend nights (10% increase in suspicion) */
    @Value("${detection.layer1.time-of-day.weekend-night-boost:1.1}")
    private double weekendNightBoost;

    /** Business hours start (default 7 AM) */
    @Value("${detection.layer1.time-of-day.business-start-hour:7}")
    private int businessStartHour;

    /** Business hours end (default 8 PM) */
    @Value("${detection.layer1.time-of-day.business-end-hour:20}")
    private int businessEndHour;

    // ========================================================================
    // MAIN ANALYSIS METHOD
    // ========================================================================

    /**
     * Analyzes current frame activity against time-of-day baseline.
     * 
     * <p>
     * This method performs the following steps:
     * </p>
     * <ol>
     * <li>Extract time slot (day_of_week, hour) from timestamp</li>
     * <li>Retrieve baseline statistics for this time slot</li>
     * <li>Handle cold start if insufficient baseline data</li>
     * <li>Calculate Z-score: Z = |X - μ| / σ</li>
     * <li>Convert Z-score to point score (0, 8, or 15)</li>
     * <li>Apply context modifiers (holiday, DST, business hours)</li>
     * <li>Asynchronously update baseline with current observation</li>
     * </ol>
     * 
     * @param bssid       The BSSID of the network being analyzed
     * @param currentRate Current frame rate (frames/minute)
     * @param timestamp   Timestamp of the detection event
     * @return Score between 0-15 indicating time anomaly level
     */
    public int analyze(String bssid, double currentRate, LocalDateTime timestamp) {
        long startTime = System.nanoTime();

        try {
            // Step 1: Extract time slot
            int dayOfWeek = timestamp.getDayOfWeek().getValue() % 7; // 0=Mon, 6=Sun
            int hour = timestamp.getHour();

            // Step 2: Retrieve baseline
            Optional<TimeOfDayBaseline> baselineOpt = baselineRepository
                    .findByBssidAndDayOfWeekAndHour(bssid, dayOfWeek, hour);

            // Step 3: Handle cold start
            if (baselineOpt.isEmpty() || baselineOpt.get().getSampleCount() < MINIMUM_SAMPLES) {
                return handleColdStart(bssid, currentRate, dayOfWeek, hour);
            }

            TimeOfDayBaseline baseline = baselineOpt.get();

            // Step 4: Calculate Z-score
            double zScore = calculateZScore(currentRate, baseline.getMean(), baseline.getStdDev());

            // Step 5: Convert to score
            int rawScore = convertZScoreToScore(zScore);

            // Step 6: Apply context modifiers
            int finalScore = applyContextModifiers(rawScore, dayOfWeek, hour, timestamp);

            // Step 7: Async baseline update
            updateBaselineAsync(bssid, dayOfWeek, hour, currentRate);

            if (log.isDebugEnabled()) {
                log.debug(
                        "TimeOfDay Analysis [BSSID:{}, Slot:({},{}), Rate:{:.2f}, μ:{:.2f}, σ:{:.2f}, Z:{:.2f}, Score:{}]",
                        bssid, dayOfWeek, hour, currentRate,
                        baseline.getMean(), baseline.getStdDev(), zScore, finalScore);
            }

            return finalScore;

        } catch (Exception e) {
            log.error("TimeOfDay analysis failed for BSSID: {}", bssid, e);
            return SCORE_NORMAL; // Graceful degradation
        } finally {
            long durationNs = System.nanoTime() - startTime;
            if (durationNs > 3_000_000) { // 3ms threshold
                log.warn("Performance Alert: TimeOfDayAnalyzer took {} ns (BSSID: {})",
                        durationNs, bssid);
            }
        }
    }

    /**
     * Overloaded method for convenience when frame rate needs to be calculated.
     * 
     * @param sourceMac  Source MAC address of deauth frames
     * @param bssid      Target network BSSID
     * @param frameCount Number of frames in the analysis window
     * @param windowSecs Analysis window duration in seconds
     * @param timestamp  Event timestamp
     * @return Score between 0-15
     */
    public int analyze(String sourceMac, String bssid, int frameCount,
            int windowSecs, LocalDateTime timestamp) {
        double currentRate = (frameCount / (double) windowSecs) * 60; // frames/minute
        return analyze(bssid, currentRate, timestamp);
    }

    // ========================================================================
    // Z-SCORE CALCULATION
    // ========================================================================

    /**
     * Calculates Z-score with edge case handling.
     * 
     * <p>
     * Formula: Z = |X - μ| / σ
     * </p>
     * 
     * <p>
     * Edge cases:
     * </p>
     * <ul>
     * <li>σ = 0: Returns 0 if X ≈ μ, else returns Z_SCORE_CAP</li>
     * <li>Result capped at Z_SCORE_CAP to prevent numerical issues</li>
     * </ul>
     * 
     * @param currentRate Current observed frame rate
     * @param mean        Baseline mean (μ)
     * @param stdDev      Baseline standard deviation (σ)
     * @return Absolute Z-score, capped at Z_SCORE_CAP
     */
    private double calculateZScore(double currentRate, double mean, double stdDev) {
        // Handle zero variance edge case
        if (stdDev < 0.001) {
            if (Math.abs(currentRate - mean) < 0.001) {
                return 0.0; // Perfect match to baseline
            } else {
                return Z_SCORE_CAP; // Maximum practical deviation
            }
        }

        double zScore = Math.abs(currentRate - mean) / stdDev;
        return Math.min(zScore, Z_SCORE_CAP);
    }

    // ========================================================================
    // Z-SCORE TO SCORE CONVERSION
    // ========================================================================

    /**
     * Converts Z-score to discrete point score.
     * 
     * <p>
     * Mapping based on normal distribution confidence intervals:
     * </p>
     * <ul>
     * <li>Z &lt; 2.0: 0 points (within 95% CI - normal variation)</li>
     * <li>2.0 ≤ Z &lt; 3.0: 8 points (outside 95%, within 99.7% - unusual)</li>
     * <li>Z ≥ 3.0: 15 points (outside 99.7% CI - highly anomalous)</li>
     * </ul>
     * 
     * <p>
     * Statistical justification:
     * </p>
     * <ul>
     * <li>95% of normal traffic has Z &lt; 2.0 → FPR ≈ 5%</li>
     * <li>Only 0.3% of normal traffic has Z ≥ 3.0 → Very low FP for max score</li>
     * </ul>
     * 
     * @param zScore Calculated Z-score (absolute value)
     * @return Score: 0, 8, or 15
     */
    private int convertZScoreToScore(double zScore) {
        if (zScore < zThresholdNormal) {
            return SCORE_NORMAL;
        } else if (zScore < zThresholdAnomalous) {
            return SCORE_UNUSUAL;
        } else {
            return SCORE_ANOMALOUS;
        }
    }

    // ========================================================================
    // COLD START HANDLING
    // ========================================================================

    /**
     * Handles scoring when insufficient baseline data exists.
     * 
     * <p>
     * Strategy:
     * </p>
     * <ol>
     * <li>Try to use global baseline (average across all time slots)</li>
     * <li>If no global baseline, use conservative default thresholds</li>
     * <li>Apply 50% penalty to reduce confidence during cold start</li>
     * </ol>
     * 
     * @param bssid       Network BSSID
     * @param currentRate Current frame rate
     * @param dayOfWeek   Day of week (0-6)
     * @param hour        Hour (0-23)
     * @return Conservative score (0-7 range during cold start)
     */
    private int handleColdStart(String bssid, double currentRate, int dayOfWeek, int hour) {
        log.debug("Cold start for BSSID:{} at slot ({},{})", bssid, dayOfWeek, hour);

        // Try to get global baseline (average across all time slots for this BSSID)
        Optional<TimeOfDayBaseline> globalOpt = baselineRepository.findGlobalAverageByBssid(bssid);

        if (globalOpt.isEmpty()) {
            // No data at all - use conservative defaults
            if (currentRate > 10.0) {
                return SCORE_UNUSUAL / 2; // Conservative 4 points
            }
            return SCORE_NORMAL;
        }

        TimeOfDayBaseline global = globalOpt.get();
        double effectiveStdDev = Math.max(global.getStdDev(), DEFAULT_STD_DEV);
        double zScore = calculateZScore(currentRate, global.getMean(), effectiveStdDev);

        int rawScore = convertZScoreToScore(zScore);

        // Apply 50% cold start penalty
        int penalizedScore = rawScore / 2;

        log.debug("Cold start scoring: rate={}, globalMean={}, Z={}, rawScore={}, penalized={}",
                currentRate, global.getMean(), zScore, rawScore, penalizedScore);

        return penalizedScore;
    }

    // ========================================================================
    // CONTEXT MODIFIERS
    // ========================================================================

    /**
     * Applies contextual modifiers to the raw score.
     * 
     * <p>
     * Modifiers:
     * </p>
     * <ul>
     * <li>Holiday: × 0.7 (expected to have unusual patterns)</li>
     * <li>DST transition: × 0.8 (time confusion possible)</li>
     * <li>Weekend night (10PM-6AM): × 1.1 (higher suspicion)</li>
     * <li>Business hours (7AM-8PM): Downgrade unusual→normal</li>
     * </ul>
     * 
     * @param score     Raw score (0, 8, or 15)
     * @param dayOfWeek Day of week (0=Mon, 6=Sun)
     * @param hour      Hour (0-23)
     * @param timestamp Full timestamp for holiday/DST checks
     * @return Modified score clamped to [0, 15]
     */
    private int applyContextModifiers(int score, int dayOfWeek, int hour, LocalDateTime timestamp) {
        double modifier = 1.0;

        // 1. Holiday check
        if (isHoliday(timestamp.toLocalDate())) {
            modifier *= holidayModifier;
            log.debug("Holiday detected - applying {} modifier", holidayModifier);
        }

        // 2. DST transition check
        if (isDstTransitionPeriod(timestamp)) {
            modifier *= dstModifier;
            log.debug("DST transition period - applying {} modifier", dstModifier);
        }

        // 3. Weekend night boost (Sat/Sun, 10PM-6AM)
        if (isWeekendNight(dayOfWeek, hour)) {
            modifier *= weekendNightBoost;
        }

        // 4. Business hours leniency - downgrade unusual to normal
        if (isBusinessHours(dayOfWeek, hour) && score == SCORE_UNUSUAL) {
            log.debug("Business hours leniency - downgrading unusual to normal");
            return SCORE_NORMAL;
        }

        int modifiedScore = (int) Math.round(score * modifier);
        return Math.max(0, Math.min(modifiedScore, SCORE_ANOMALOUS));
    }

    /**
     * Checks if a date is a holiday from the calendar.
     */
    private boolean isHoliday(LocalDate date) {
        try {
            return holidayRepository.existsByHolidayDate(date);
        } catch (Exception e) {
            log.warn("Failed to check holiday calendar: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Checks if timestamp is within 24 hours of a DST transition.
     */
    private boolean isDstTransitionPeriod(LocalDateTime timestamp) {
        try {
            ZonedDateTime zdt = timestamp.atZone(ZoneId.systemDefault());
            ZoneRules rules = zdt.getZone().getRules();

            ZoneOffsetTransition next = rules.nextTransition(zdt.toInstant());
            ZoneOffsetTransition prev = rules.previousTransition(zdt.toInstant());

            Duration toNext = (next != null)
                    ? Duration.between(zdt.toInstant(), next.getInstant())
                    : Duration.ofDays(365);
            Duration fromPrev = (prev != null)
                    ? Duration.between(prev.getInstant(), zdt.toInstant())
                    : Duration.ofDays(365);

            return toNext.toHours() <= 24 || fromPrev.toHours() <= 24;
        } catch (Exception e) {
            log.warn("Failed to check DST transition: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Checks if this is a weekend night (higher suspicion for attacks).
     */
    private boolean isWeekendNight(int dayOfWeek, int hour) {
        boolean isWeekend = (dayOfWeek == 5 || dayOfWeek == 6); // Sat=5, Sun=6
        boolean isNight = (hour >= 22 || hour <= 6);
        return isWeekend && isNight;
    }

    /**
     * Checks if this is within business hours (leniency for unusual scores).
     */
    private boolean isBusinessHours(int dayOfWeek, int hour) {
        boolean isWeekday = (dayOfWeek >= 0 && dayOfWeek <= 4); // Mon-Fri
        boolean isWorkHours = (hour >= businessStartHour && hour < businessEndHour);
        return isWeekday && isWorkHours;
    }

    // ========================================================================
    // BASELINE UPDATE (ASYNC)
    // ========================================================================

    /**
     * Asynchronously updates baseline statistics using Welford's EMA algorithm.
     * 
     * <p>
     * Update equations:
     * </p>
     * 
     * <pre>
     * μ_new = α × X + (1 - α) × μ_old
     * δ = X - μ_old
     * δ' = X - μ_new
     * σ²_new = (1 - α) × (σ²_old + α × δ × δ')
     * σ_new = √(σ²_new)
     * </pre>
     * 
     * @param bssid       Network BSSID
     * @param dayOfWeek   Day of week (0-6)
     * @param hour        Hour (0-23)
     * @param currentRate Observed frame rate
     */
    @Async
    public void updateBaselineAsync(String bssid, int dayOfWeek, int hour, double currentRate) {
        try {
            TimeOfDayBaseline baseline = baselineRepository
                    .findByBssidAndDayOfWeekAndHour(bssid, dayOfWeek, hour)
                    .orElseGet(() -> createNewBaseline(bssid, dayOfWeek, hour));

            if (baseline.getSampleCount() == 0) {
                // First observation
                baseline.setMean(currentRate);
                baseline.setVariance(0.0);
                baseline.setStdDev(DEFAULT_STD_DEV);
                baseline.setSampleCount(1);
            } else {
                // Welford's algorithm with EMA
                double oldMean = baseline.getMean();
                double oldVariance = baseline.getVariance();

                double newMean = EMA_ALPHA * currentRate + (1 - EMA_ALPHA) * oldMean;
                double delta = currentRate - oldMean;
                double deltaPrime = currentRate - newMean;
                double newVariance = (1 - EMA_ALPHA) * (oldVariance + EMA_ALPHA * delta * deltaPrime);

                baseline.setMean(newMean);
                baseline.setVariance(Math.max(0, newVariance));
                baseline.setStdDev(Math.sqrt(Math.max(0, newVariance)));
                baseline.setSampleCount(Math.min(baseline.getSampleCount() + 1, 1000));
            }

            baseline.setLastUpdated(LocalDateTime.now());
            baselineRepository.save(baseline);

            log.trace("Updated baseline [BSSID:{}, Slot:({},{}), μ={}, σ={}, n={}]",
                    bssid, dayOfWeek, hour, baseline.getMean(),
                    baseline.getStdDev(), baseline.getSampleCount());

        } catch (Exception e) {
            log.warn("Failed to update baseline for BSSID:{} slot:({},{}): {}",
                    bssid, dayOfWeek, hour, e.getMessage());
        }
    }

    /**
     * Creates a new baseline entity with default values.
     */
    private TimeOfDayBaseline createNewBaseline(String bssid, int dayOfWeek, int hour) {
        TimeOfDayBaseline baseline = new TimeOfDayBaseline();
        baseline.setBssid(bssid);
        baseline.setDayOfWeek(dayOfWeek);
        baseline.setHour(hour);
        baseline.setMean(0.0);
        baseline.setVariance(0.0);
        baseline.setStdDev(DEFAULT_STD_DEV);
        baseline.setSampleCount(0);
        baseline.setLastUpdated(LocalDateTime.now());
        return baseline;
    }
}
