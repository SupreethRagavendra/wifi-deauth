package com.wifi.security.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Batch Detection Request for processing multiple frames at once.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BatchDetectionRequest {

    /**
     * Unique batch request identifier.
     */
    private String batchId;

    /**
     * List of individual detection requests.
     * Maximum 100 requests per batch.
     */
    @NotEmpty(message = "At least one detection request is required")
    @Size(max = 100, message = "Maximum 100 requests per batch")
    @Valid
    private List<DetectionRequest> requests;

    /**
     * Processing priority for the entire batch.
     */
    @Builder.Default
    private Integer priority = 0;

    /**
     * Flag to process sequentially instead of parallel.
     */
    @Builder.Default
    private boolean sequential = false;
}
