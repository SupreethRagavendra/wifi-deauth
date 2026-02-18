package com.wifi.security.service.layer1;

import com.wifi.security.dto.request.DetectionRequest;
import com.wifi.security.dto.response.DetectionResponse;
import com.wifi.security.dto.response.AnalyzerScore;
import com.wifi.security.exception.DetectionServiceException;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.time.LocalDateTime;
import java.util.concurrent.*;

/**
 * Layer1Service - Orchestrator for Layer 1 Detection Analyzers.
 * 
 * Coordinates parallel execution of all 4 analyzers:
 * - RateAnalyzer: Frame rate analysis
 * - SequenceValidator: Sequence number validation
 * - TimeAnomalyDetector: Temporal anomaly detection
 * - SessionStateChecker: Session context validation
 * 
 * Features:
 * - Parallel async execution with CompletableFuture
 * - Configurable timeout (max 5ms for Layer 1)
 * - Graceful degradation on partial failures
 * - Comprehensive metrics and monitoring
 */
@Service
@Slf4j
public class Layer1Service {

    private final RateAnalyzer rateAnalyzer;
    private final SequenceValidator sequenceValidator;
    private final TimeAnomalyDetector timeAnomalyDetector;
    private final SessionStateChecker sessionStateChecker;
    private final MeterRegistry meterRegistry;
    private final com.wifi.security.repository.DetectionEventRepository eventRepository;

    // Executor for async analyzer execution
    private final ExecutorService analyzerExecutor;

    // Metrics
    private Counter detectionCounter;
    private Counter timeoutCounter;
    private Counter errorCounter;
    private Timer detectionTimer;

    // Configuration
    @Value("${detection.layer1.timeout-ms:5}")
    private long timeoutMs;

    @Value("${detection.layer1.attack-threshold:50}")
    private int attackThreshold;

    @Value("${detection.layer1.suspicious-threshold:30}")
    private int suspiciousThreshold;

    @Value("${detection.layer1.warning-threshold:15}")
    private int warningThreshold;

    /**
     * Constructor with dependency injection.
     */
    public Layer1Service(
            RateAnalyzer rateAnalyzer,
            SequenceValidator sequenceValidator,
            TimeAnomalyDetector timeAnomalyDetector,
            SessionStateChecker sessionStateChecker,
            MeterRegistry meterRegistry,
            com.wifi.security.repository.DetectionEventRepository eventRepository) {
        this.rateAnalyzer = rateAnalyzer;
        this.sequenceValidator = sequenceValidator;
        this.timeAnomalyDetector = timeAnomalyDetector;
        this.sessionStateChecker = sessionStateChecker;
        this.meterRegistry = meterRegistry;
        this.eventRepository = eventRepository;

        // Create a dedicated thread pool for analyzers
        // Using fixed pool to control parallelism
        this.analyzerExecutor = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "layer1-analyzer");
            t.setDaemon(true);
            return t;
        });
    }

    @PostConstruct
    public void initMetrics() {
        this.detectionCounter = Counter.builder("detection.layer1.requests")
                .description("Total Layer 1 detection requests")
                .register(meterRegistry);

        this.timeoutCounter = Counter.builder("detection.layer1.timeouts")
                .description("Layer 1 detection timeouts")
                .register(meterRegistry);

        this.errorCounter = Counter.builder("detection.layer1.errors")
                .description("Layer 1 detection errors")
                .register(meterRegistry);

        this.detectionTimer = Timer.builder("detection.layer1.duration")
                .description("Layer 1 detection duration")
                .register(meterRegistry);
    }

    /**
     * Performs Layer 1 analysis on a frame.
     * Executes all 4 analyzers in parallel and combines results.
     *
     * @param request The detection request containing frame data
     * @return DetectionResponse with combined analysis results
     */
    public DetectionResponse analyze(DetectionRequest request) {
        long startTime = System.nanoTime();
        detectionCounter.increment();

        log.debug("Starting Layer 1 analysis for source: {}, bssid: {}",
                request.getSourceMac(), request.getBssid());

        try {
            // Launch all analyzers in parallel
            CompletableFuture<Integer> rateFuture = CompletableFuture.supplyAsync(
                    () -> rateAnalyzer.analyzeRate(request.getSourceMac(), request.getBssid()),
                    analyzerExecutor);

            CompletableFuture<Integer> seqFuture = CompletableFuture.supplyAsync(
                    () -> sequenceValidator.validate(request.getSourceMac(), request.getBssid()),
                    analyzerExecutor);

            CompletableFuture<Integer> timeFuture = CompletableFuture.supplyAsync(
                    () -> timeAnomalyDetector.detectAnomalies(request.getSourceMac(), request.getBssid()),
                    analyzerExecutor);

            CompletableFuture<Integer> sessionFuture = CompletableFuture.supplyAsync(
                    () -> sessionStateChecker.checkSessionState(request.getSourceMac(), request.getBssid()),
                    analyzerExecutor);

            // Combine all futures
            CompletableFuture<Void> allAnalyzers = CompletableFuture.allOf(
                    rateFuture, seqFuture, timeFuture, sessionFuture);

            // Wait with timeout
            try {
                allAnalyzers.orTimeout(timeoutMs, TimeUnit.MILLISECONDS).join();
            } catch (CompletionException e) {
                if (e.getCause() instanceof TimeoutException) {
                    timeoutCounter.increment();
                    log.warn("Layer 1 analysis timeout for source: {}", request.getSourceMac());
                    // Continue with partial results
                }
            }

            // Collect results (with fallback for timed-out analyzers)
            int rateScore = getScoreOrDefault(rateFuture, "RateAnalyzer");
            int seqScore = getScoreOrDefault(seqFuture, "SequenceValidator");
            int timeScore = getScoreOrDefault(timeFuture, "TimeAnomalyDetector");
            int sessionScore = getScoreOrDefault(sessionFuture, "SessionStateChecker");

            // Calculate combined score
            int combinedScore = calculateCombinedScore(rateScore, seqScore, timeScore, sessionScore);

            // Determine threat level
            String threatLevel = determineThreatLevel(combinedScore);

            // Build response
            DetectionResponse response = DetectionResponse.builder()
                    .requestId(request.getRequestId())
                    .sourceMac(request.getSourceMac())
                    .bssid(request.getBssid())
                    .combinedScore(combinedScore)
                    .threatLevel(threatLevel)
                    .isAttackDetected(combinedScore >= attackThreshold)
                    .analyzerScores(AnalyzerScore.builder()
                            .rateAnalyzerScore(rateScore)
                            .sequenceValidatorScore(seqScore)
                            .timeAnomalyScore(timeScore)
                            .sessionStateScore(sessionScore)
                            .build())
                    .analysisTimestamp(LocalDateTime.now())
                    .processingTimeMs(getElapsedMs(startTime))
                    .layer("LAYER_1")
                    .build();

            // Record metrics
            detectionTimer.record(getElapsedMs(startTime), TimeUnit.MILLISECONDS);

            log.info("Layer 1 analysis complete [Source: {}, Score: {}, Threat: {}, Time: {}ms]",
                    request.getSourceMac(), combinedScore, threatLevel, response.getProcessingTimeMs());

            // NEW: Save anomaly to database if it exceeds threshold
            if (combinedScore >= warningThreshold) {
                saveAnomaly(response);
            }

            return response;

        } catch (Exception e) {
            errorCounter.increment();
            log.error("Layer 1 analysis failed for source: {}", request.getSourceMac(), e);
            throw new DetectionServiceException("Layer 1 analysis failed", e);
        }
    }

    /**
     * Gets score from a future or returns default on failure.
     */
    private int getScoreOrDefault(CompletableFuture<Integer> future, String analyzerName) {
        try {
            if (future.isDone() && !future.isCompletedExceptionally()) {
                return future.getNow(0);
            }
        } catch (Exception e) {
            log.warn("{} failed to complete: {}", analyzerName, e.getMessage());
        }
        return 0; // Graceful degradation
    }

    /**
     * Calculates combined score from all analyzers.
     * Uses weighted average with emphasis on rate analysis.
     */
    private int calculateCombinedScore(int rateScore, int seqScore, int timeScore, int sessionScore) {
        // Weighted scoring:
        // - Rate Analysis: 30% (primary indicator)
        // - Sequence Validation: 25% (strong indicator)
        // - Time Anomaly: 25% (automation indicator)
        // - Session State: 20% (context validation)

        double weightedScore = (rateScore * 0.30) +
                (seqScore * 0.25) +
                (timeScore * 0.25) +
                (sessionScore * 0.20);

        return (int) Math.round(weightedScore);
    }

    /**
     * Determines threat level based on combined score.
     */
    private String determineThreatLevel(int score) {
        if (score >= attackThreshold) {
            return "CRITICAL";
        } else if (score >= suspiciousThreshold) {
            return "HIGH";
        } else if (score >= warningThreshold) {
            return "MEDIUM";
        } else if (score > 0) {
            return "LOW";
        }
        return "NONE";
    }

    /**
     * Calculates elapsed time in milliseconds.
     */
    private long getElapsedMs(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000;
    }

    /**
     * Batch analysis for multiple frames.
     * Useful for bulk processing of captured packets.
     */
    public CompletableFuture<DetectionResponse[]> analyzeBatch(DetectionRequest[] requests) {
        CompletableFuture<DetectionResponse>[] futures = new CompletableFuture[requests.length];

        for (int i = 0; i < requests.length; i++) {
            final DetectionRequest request = requests[i];
            futures[i] = CompletableFuture.supplyAsync(() -> analyze(request), analyzerExecutor);
        }

        return CompletableFuture.allOf(futures)
                .thenApply(v -> {
                    DetectionResponse[] results = new DetectionResponse[futures.length];
                    for (int i = 0; i < futures.length; i++) {
                        results[i] = futures[i].join();
                    }
                    return results;
                });
    }

    /**
     * Health check for the detection service.
     */
    public boolean isHealthy() {
        try {
            // Verify analyzer components are accessible
            return rateAnalyzer != null &&
                    sequenceValidator != null &&
                    timeAnomalyDetector != null &&
                    sessionStateChecker != null &&
                    !analyzerExecutor.isShutdown();
        } catch (Exception e) {
            log.error("Health check failed", e);
            return false;
        }
    }

    /**
     * Graceful shutdown of the executor.
     */
    public void shutdown() {
        log.info("Shutting down Layer1Service executor...");
        analyzerExecutor.shutdown();
        try {
            if (!analyzerExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                analyzerExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            analyzerExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Analyze a batch of packets from PacketService and save anomalies.
     */
    public void analyzeBatch(java.util.List<com.wifi.security.dto.request.PacketDTO> packets) {
        DetectionRequest[] requests = packets.stream()
                .map(p -> DetectionRequest.builder()
                        .requestId(java.util.UUID.randomUUID().toString())
                        .sourceMac(p.getSourceMac())
                        .bssid(p.getBssid())
                        .frameType(p.getFrameType())
                        .rssi(p.getRssi())
                        .timestamp(p.getTimestamp())
                        .build())
                .toArray(DetectionRequest[]::new);

        analyzeBatch(requests).thenAccept(results -> {
            for (DetectionResponse r : results) {
                if (r.getCombinedScore() >= warningThreshold) {
                    saveAnomaly(r);
                }
            }
        });
    }

    private void saveAnomaly(DetectionResponse response) {
        try {
            com.wifi.security.entity.detection.DetectionEvent event = com.wifi.security.entity.detection.DetectionEvent
                    .builder()
                    .attackerMac(response.getSourceMac())
                    .targetBssid(response.getBssid())
                    .layer1Score(response.getCombinedScore())
                    .totalScore(response.getCombinedScore())
                    .severity(com.wifi.security.entity.detection.DetectionEvent.Severity
                            .valueOf(response.getThreatLevel()))
                    .detectedAt(response.getAnalysisTimestamp())
                    .attackStart(response.getAnalysisTimestamp())
                    .frameCount(1) // Single frame event
                    .build();

            eventRepository.save(event);
        } catch (Exception e) {
            log.error("Failed to save detection event", e);
        }
    }

    public java.util.List<com.wifi.security.entity.detection.DetectionEvent> getRecentEvents() {
        return eventRepository.findTop20ByOrderByDetectedAtDesc();
    }

    /**
     * Clear all detection events from database (for demo/testing purposes).
     */
    public void clearAllEvents() {
        try {
            eventRepository.deleteAll();
            log.info("Cleared all detection events from database");
        } catch (Exception e) {
            log.error("Failed to clear detection events", e);
        }
    }
}
