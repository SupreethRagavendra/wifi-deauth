package com.wifi.security.service.layer1;

import com.wifi.security.dto.request.DetectionRequest;
import com.wifi.security.dto.response.DetectionResponse;
import com.wifi.security.dto.response.AnalyzerScore;
import com.wifi.security.exception.DetectionServiceException;
import com.wifi.security.dto.AlertDTO;
import com.wifi.security.service.AlertService;
import com.wifi.security.entity.detection.DetectionEvent;
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
    private final com.wifi.security.repository.WiFiNetworkRepository wifiNetworkRepository;
    private final AlertService alertService;

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
            com.wifi.security.repository.DetectionEventRepository eventRepository,
            AlertService alertService,
            com.wifi.security.repository.WiFiNetworkRepository wifiNetworkRepository) {
        this.rateAnalyzer = rateAnalyzer;
        this.sequenceValidator = sequenceValidator;
        this.timeAnomalyDetector = timeAnomalyDetector;
        this.sessionStateChecker = sessionStateChecker;
        this.meterRegistry = meterRegistry;
        this.eventRepository = eventRepository;
        this.alertService = alertService;
        this.wifiNetworkRepository = wifiNetworkRepository;

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
                    .destMac(request.getDestMac())
                    .realAttackerMac(request.getRealAttackerMac())
                    .isSpoofed(request.getIsSpoofed())
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

            log.info("Layer 1 analysis complete [Source: {}, Score: {}, Threat: {}ms]",
                    request.getSourceMac(), combinedScore, threatLevel, response.getProcessingTimeMs());

            // NEW: Save all anomaly events to database permanently
            saveAnomaly(response);

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
        // Weighted scoring based on User Flowchart:
        // - Rate Analysis: 35 pts
        // - Sequence Validation: 25 pts
        // - Time Anomaly: 15 pts
        // - Session State: 20 pts
        // Total max score: 95 pts

        double weightedScore = (rateScore * 0.35) +
                (seqScore * 0.25) +
                (timeScore * 0.15) +
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
        }
        return "LOW";
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
                        .realAttackerMac(p.getRealAttackerMac())
                        .isSpoofed(p.getIsSpoofed())
                        .build())
                .toArray(DetectionRequest[]::new);

        analyzeBatch(requests).thenAccept(results -> {
            for (DetectionResponse r : results) {
                saveAnomaly(r);
            }
        });
    }

    private synchronized void saveAnomaly(DetectionResponse response) {
        // Save ALL events so that:
        // 1) updateWithMlScores can find them by ID and upgrade severity after ML runs
        // 2) Per-analyzer sub-scores are preserved for the frontend Heuristics
        // Breakdown

        try {
            // Find appropriate institute context based on target AP (BSSID)
            String instituteId = null;
            if (response.getBssid() != null && !response.getBssid().isEmpty()) {
                instituteId = wifiNetworkRepository.findFirstByBssid(response.getBssid())
                        .map(n -> n.getInstitute() != null ? n.getInstitute().getInstituteId() : null)
                        .orElse(null);
            }

            // Fix: Check for existing event to prevent Event Inflation
            java.util.List<com.wifi.security.entity.detection.DetectionEvent> recent = eventRepository
                    .findTop100ByOrderByDetectedAtDesc();
            java.time.LocalDateTime cutoff = java.time.LocalDateTime.now().minusSeconds(15);
            com.wifi.security.entity.detection.DetectionEvent existingEvent = recent.stream()
                    .filter(e -> response.getSourceMac().equals(e.getAttackerMac()))
                    .filter(e -> e.getDetectedAt() != null && e.getDetectedAt().isAfter(cutoff))
                    .findFirst()
                    .orElse(null);

            com.wifi.security.entity.detection.DetectionEvent savedEvent;

            if (existingEvent != null) {
                // Update existing event instead of creating a new row
                existingEvent
                        .setFrameCount((existingEvent.getFrameCount() != null ? existingEvent.getFrameCount() : 1) + 1);

                long duration = java.time.Duration.between(existingEvent.getDetectedAt(), java.time.LocalDateTime.now())
                        .toMillis();
                existingEvent.setAttackDurationMs((int) Math.max(1000, duration));

                // Keep the max score
                if (response.getCombinedScore() > existingEvent.getLayer1Score()) {
                    existingEvent.setLayer1Score(response.getCombinedScore());
                    existingEvent.setTotalScore(response.getCombinedScore());
                    existingEvent.setSeverity(com.wifi.security.entity.detection.DetectionEvent.Severity
                            .valueOf(response.getThreatLevel()));
                }

                savedEvent = eventRepository.save(existingEvent);
            } else {
                com.wifi.security.entity.detection.DetectionEvent event = com.wifi.security.entity.detection.DetectionEvent
                        .builder()
                        .attackerMac(response.getSourceMac())
                        .targetMac(response.getDestMac() != null ? response.getDestMac() : response.getSourceMac()) // Use
                                                                                                                    // destination
                                                                                                                    // MAC
                                                                                                                    // as
                                                                                                                    // victim,
                                                                                                                    // fallback
                                                                                                                    // to
                                                                                                                    // source
                        .realAttackerMac(response.getRealAttackerMac())
                        .isSpoofed(response.getIsSpoofed())
                        .targetBssid(response.getBssid())
                        .instituteId(instituteId) // Ensure multi-tenant dashboards work
                        .layer1Score(response.getCombinedScore())
                        .totalScore(response.getCombinedScore())
                        .rateAnalyzerScore(
                                response.getAnalyzerScores() != null
                                        ? response.getAnalyzerScores().getRateAnalyzerScore()
                                        : 0)
                        .seqValidatorScore(response.getAnalyzerScores() != null
                                ? response.getAnalyzerScores().getSequenceValidatorScore()
                                : 0)
                        .timeAnomalyScore(
                                response.getAnalyzerScores() != null
                                        ? response.getAnalyzerScores().getTimeAnomalyScore()
                                        : 0)
                        .sessionStateScore(
                                response.getAnalyzerScores() != null
                                        ? response.getAnalyzerScores().getSessionStateScore()
                                        : 0)
                        .severity(com.wifi.security.entity.detection.DetectionEvent.Severity
                                .valueOf(response.getThreatLevel()))
                        .detectedAt(response.getAnalysisTimestamp())
                        .attackStart(response.getAnalysisTimestamp())
                        .frameCount(1) // Single frame event
                        .attackDurationMs(1000) // 1 second default
                        .build();

                savedEvent = eventRepository.save(event);
            }

            // Store the DB-assigned event ID back into the response so DetectionService
            // can pass it to updateWithMlScores() for a precise update (no race condition)
            response.setLastSavedEventId(savedEvent.getEventId());

            // Only broadcast to frontend if severity is MEDIUM or higher.
            // LOW events are NOT broadcast here — DetectionService.triggerAttack()
            // will broadcast with the correct final score after ML runs.
            // This prevents 3x duplicate events in the frontend feed.
            if (savedEvent.getSeverity() != com.wifi.security.entity.detection.DetectionEvent.Severity.LOW) {
                AlertDTO alert = AlertDTO.builder()
                        .type(savedEvent
                                .getSeverity() == com.wifi.security.entity.detection.DetectionEvent.Severity.CRITICAL
                                || savedEvent
                                        .getSeverity() == com.wifi.security.entity.detection.DetectionEvent.Severity.HIGH
                                                ? "CRITICAL_ALERT"
                                                : "MONITOR_ALERT")
                        .severity(savedEvent.getSeverity().name())
                        .attackerMac(savedEvent.getAttackerMac())
                        .targetBssid(savedEvent.getTargetBssid())
                        .targetMac(savedEvent.getTargetMac())
                        .message("Layer 1 analysis: " + savedEvent.getSeverity().name() + " threat detected from "
                                + savedEvent.getAttackerMac())
                        .score(savedEvent.getTotalScore() != null ? savedEvent.getTotalScore()
                                : savedEvent.getLayer1Score())
                        .layer2Score(savedEvent.getLayer2Score())
                        .layer3Score(savedEvent.getLayer3Score())
                        .rateAnalyzerScore(savedEvent.getRateAnalyzerScore())
                        .seqValidatorScore(savedEvent.getSeqValidatorScore())
                        .timeAnomalyScore(savedEvent.getTimeAnomalyScore())
                        .sessionStateScore(savedEvent.getSessionStateScore())
                        .mlConfidence(savedEvent.getMlConfidence())
                        .mlPrediction(savedEvent.getMlPrediction())
                        .isSpoofed(savedEvent.getIsSpoofed())
                        .attackerConfidence(savedEvent.getAttackerConfidence())
                        .detectionMethod(savedEvent.getDetectionMethod())
                        .rssiDeviation(savedEvent.getRssiDeviation())
                        .realAttackerMac(savedEvent.getRealAttackerMac())
                        .packetCount(savedEvent.getFrameCount() != null ? savedEvent.getFrameCount() : 1)
                        .timestamp(java.time.Instant.now().toString())
                        .build();
                alertService.processAlert(alert);
            }

            log.info("Saved detection event: source={}, score={}, severity={}, eventId={}",
                    response.getSourceMac(), response.getCombinedScore(), response.getThreatLevel(),
                    savedEvent.getEventId());
        } catch (Exception e) {
            log.error("Failed to save detection event", e);
        }
    }

    public java.util.List<com.wifi.security.entity.detection.DetectionEvent> getRecentEvents() {
        return eventRepository.findTop100ByOrderByDetectedAtDesc();
    }

    public java.util.List<com.wifi.security.entity.detection.DetectionEvent> getActiveThreats() {
        LocalDateTime cutoff = LocalDateTime.now().minusSeconds(30);
        java.util.List<com.wifi.security.entity.detection.DetectionEvent> events = eventRepository
                .findByDetectedAtAfterOrderByDetectedAtDesc(cutoff);
        log.debug("Found {} active threats from last 30 seconds", events.size());
        return events;
    }

    public boolean isCurrentlyUnderAttack() {
        LocalDateTime cutoff = LocalDateTime.now().minusSeconds(15);
        java.util.List<com.wifi.security.entity.detection.DetectionEvent> recent = eventRepository
                .findByDetectedAtAfterOrderByDetectedAtDesc(cutoff);

        boolean underAttack = recent.stream()
                .anyMatch(e -> e.getSeverity().name().equals("CRITICAL") ||
                        e.getSeverity().name().equals("HIGH") ||
                        e.getSeverity().name().equals("MEDIUM"));

        log.debug("Attack status check: {} critical/high events in last 15 seconds = {}",
                recent.size(), underAttack);
        return underAttack;
    }

    /**
     * Update the most recent detection event for a source MAC with ML analysis
     * results.
     * Called by DetectionService after Layer 2 ML runs.
     * Prefers eventId (fast, precise) and falls back to MAC-based lookup if eventId
     * is null.
     */
    public void updateWithMlScores(Long eventId, String sourceMac, int mlScore, double mlConfidence,
            String mlPrediction, String modelAgreement, Integer layer3Score, String layer3Notes, int finalScore) {
        log.info("updateWithMlScores called for eventId={}, sourceMac={}, mlScore={}, confidence={}",
                eventId, sourceMac, mlScore, mlConfidence);
        try {
            // Prefer eventId lookup — eliminates race condition when multiple events for
            // the same MAC are saved within the same millisecond.
            if (eventId != null) {
                eventRepository.findById(eventId).ifPresent(event -> applyMlScores(
                        event, mlScore, mlConfidence, mlPrediction, modelAgreement,
                        layer3Score, layer3Notes, finalScore));
                return;
            }

            // Fallback: MAC-based lookup (used when event was LOW and not persisted)
            java.util.List<com.wifi.security.entity.detection.DetectionEvent> recent = eventRepository
                    .findTop100ByOrderByDetectedAtDesc();

            recent.stream()
                    .filter(e -> sourceMac.equals(e.getAttackerMac()))
                    .findFirst()
                    .ifPresent(event -> applyMlScores(
                            event, mlScore, mlConfidence, mlPrediction, modelAgreement,
                            layer3Score, layer3Notes, finalScore));
        } catch (Exception e) {
            log.error("Failed to update event with ML scores for {}: {}", sourceMac, e.getMessage());
        }
    }

    private void applyMlScores(com.wifi.security.entity.detection.DetectionEvent event,
            int mlScore, double mlConfidence, String mlPrediction, String modelAgreement,
            Integer layer3Score, String layer3Notes, int finalScore) {
        event.setLayer2Score(mlScore);
        event.setMlConfidence(mlConfidence);
        event.setMlPrediction(mlPrediction);
        event.setModelAgreement(modelAgreement);
        if (layer3Score != null) {
            event.setLayer3Score(layer3Score);
        }
        if (layer3Notes != null) {
            event.setLayer3Notes(layer3Notes);
        }
        event.setTotalScore(finalScore);
        // Re-evaluate severity based on final score
        if (finalScore >= attackThreshold) {
            event.setSeverity(com.wifi.security.entity.detection.DetectionEvent.Severity.CRITICAL);
        } else if (finalScore >= suspiciousThreshold) {
            event.setSeverity(com.wifi.security.entity.detection.DetectionEvent.Severity.HIGH);
        } else if (finalScore >= warningThreshold) {
            event.setSeverity(com.wifi.security.entity.detection.DetectionEvent.Severity.MEDIUM);
        }
        eventRepository.save(event);
        log.info("Updated event (id={}) with ML: ml={}, conf={}, final={}, severity={}",
                event.getEventId(), mlScore, mlConfidence, finalScore, event.getSeverity());
        // NOTE: No SSE re-broadcast here — DetectionService.triggerAttack()
        // already broadcasts the final score. Double-broadcasting caused
        // the frontend to show 3x the actual number of events.
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
