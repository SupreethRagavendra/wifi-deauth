package com.wifi.security.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * AnalyzerScore DTO containing individual scores from each Layer 1 analyzer.
 * Provides transparency into how the combined score was calculated.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AnalyzerScore {

    /**
     * Score from RateAnalyzer (0-35).
     * Measures frame rate anomalies.
     */
    private int rateAnalyzerScore;

    /**
     * Score from SequenceValidator (0-35).
     * Measures sequence number anomalies.
     */
    private int sequenceValidatorScore;

    /**
     * Score from TimeAnomalyDetector (0-35).
     * Measures timing pattern anomalies.
     */
    private int timeAnomalyScore;

    /**
     * Score from SessionStateChecker (0-35).
     * Measures session context anomalies.
     */
    private int sessionStateScore;

    /**
     * Get the maximum individual score.
     */
    public int getMaxScore() {
        return Math.max(
                Math.max(rateAnalyzerScore, sequenceValidatorScore),
                Math.max(timeAnomalyScore, sessionStateScore));
    }

    /**
     * Get the average of all scores.
     */
    public double getAverageScore() {
        return (rateAnalyzerScore + sequenceValidatorScore + timeAnomalyScore + sessionStateScore) / 4.0;
    }

    /**
     * Count how many analyzers flagged suspicious activity (score > 0).
     */
    public int getActiveAnalyzerCount() {
        int count = 0;
        if (rateAnalyzerScore > 0)
            count++;
        if (sequenceValidatorScore > 0)
            count++;
        if (timeAnomalyScore > 0)
            count++;
        if (sessionStateScore > 0)
            count++;
        return count;
    }

    /**
     * Get a summary description of the scores.
     */
    public String getSummary() {
        return String.format("Rate=%d, Seq=%d, Time=%d, Session=%d (Avg=%.1f, Max=%d)",
                rateAnalyzerScore, sequenceValidatorScore, timeAnomalyScore, sessionStateScore,
                getAverageScore(), getMaxScore());
    }
}
