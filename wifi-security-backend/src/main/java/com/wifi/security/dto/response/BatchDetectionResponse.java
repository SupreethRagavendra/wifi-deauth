package com.wifi.security.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Batch Detection Response containing results for multiple frames.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class BatchDetectionResponse {

    /**
     * Batch ID for correlation.
     */
    private String batchId;

    /**
     * Total number of requests processed.
     */
    private int totalProcessed;

    /**
     * Number of successful analyses.
     */
    private int successCount;

    /**
     * Number of failed analyses.
     */
    private int failureCount;

    /**
     * Number of attacks detected.
     */
    private int attacksDetected;

    /**
     * Highest threat level in the batch.
     */
    private String highestThreatLevel;

    /**
     * Individual detection results.
     */
    private List<DetectionResponse> results;

    /**
     * Total processing time for the batch.
     */
    private long totalProcessingTimeMs;

    /**
     * Timestamp of batch completion.
     */
    private LocalDateTime completedAt;

    /**
     * Summary statistics.
     */
    private BatchStatistics statistics;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class BatchStatistics {
        private double averageScore;
        private int maxScore;
        private int minScore;
        private double averageProcessingTimeMs;
        private int criticalCount;
        private int highCount;
        private int mediumCount;
        private int lowCount;
    }
}
