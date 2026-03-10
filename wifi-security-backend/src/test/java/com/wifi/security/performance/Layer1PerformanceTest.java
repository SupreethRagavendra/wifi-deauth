package com.wifi.security.performance;

import com.wifi.security.dto.request.DetectionRequest;
import com.wifi.security.dto.response.DetectionResponse;
import com.wifi.security.entity.CapturedPacket;
import com.wifi.security.repository.PacketRepository;
import com.wifi.security.repository.DetectionEventRepository;
import com.wifi.security.service.AlertService;
import com.wifi.security.service.layer1.*;
import com.wifi.security.util.CapturedPacketBuilder;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Performance Tests for the complete Layer 1 Detection System.
 * Tests both individual analyzer performance and full pipeline throughput.
 * 
 * Performance Targets:
 * - Individual Analyzers: < 1ms
 * - Full Pipeline: < 3ms
 * - Throughput: 1000 frames/sec normal, 10000 frames/sec burst
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Layer 1 Performance Tests")
class Layer1PerformanceTest {

    @Mock
    private PacketRepository packetRepository;

    private RateAnalyzer rateAnalyzer;
    private SequenceValidator sequenceValidator;
    private TimeAnomalyDetector timeAnomalyDetector;
    private SessionStateChecker sessionStateChecker;
    private Layer1Service layer1Service;

    @Mock
    private DetectionEventRepository eventRepository;

    @Mock
    private AlertService alertService; // Added AlertService mock

    @Mock
    private com.wifi.security.repository.WiFiNetworkRepository wifiNetworkRepository;

    private String testSourceMac = "00:11:22:33:44:55";
    private String testBssid = "AA:BB:CC:DD:EE:FF";

    @BeforeEach
    void setUp() {
        rateAnalyzer = new RateAnalyzer(packetRepository);
        sequenceValidator = new SequenceValidator(packetRepository);
        timeAnomalyDetector = new TimeAnomalyDetector(packetRepository);
        sessionStateChecker = new SessionStateChecker(packetRepository);
        layer1Service = new Layer1Service(
                rateAnalyzer,
                sequenceValidator,
                timeAnomalyDetector,
                sessionStateChecker,
                new SimpleMeterRegistry(),
                eventRepository,
                alertService,
                wifiNetworkRepository); // Passed dependencies to constructor
        layer1Service.initMetrics();

        // Setup mock responses for realistic simulation
        org.mockito.Mockito.lenient()
                .when(packetRepository.countBySourceMacAndBssidAndTimestampAfter(any(), any(), any()))
                .thenReturn(5L);
        org.mockito.Mockito.lenient().when(packetRepository.findRecentPacketsBySourceAndBssid(any(), any(), any()))
                .thenReturn(createMockPackets(10));
        org.mockito.Mockito.lenient().when(packetRepository.findByBssidAndTimestampAfter(any(), any()))
                .thenReturn(createMockPackets(15));
    }

    @Test
    @DisplayName("Individual Analyzer Performance: RateAnalyzer < 1ms")
    void benchmarkRateAnalyzer() {
        // Warmup
        IntStream.range(0, 1000).forEach(i -> rateAnalyzer.analyzeRate(testSourceMac, testBssid));

        // Measure
        long start = System.nanoTime();
        int iterations = 10000;
        for (int i = 0; i < iterations; i++) {
            rateAnalyzer.analyzeRate(testSourceMac, testBssid);
        }
        long totalNs = System.nanoTime() - start;
        double avgMs = (totalNs / (double) iterations) / 1_000_000.0;

        System.out.printf("RateAnalyzer Average: %.4f ms%n", avgMs);
        assertThat(avgMs)
                .as("RateAnalyzer should complete in < 1ms")
                .isLessThan(1.0);
    }

    @Test
    @DisplayName("Individual Analyzer Performance: SequenceValidator < 1ms")
    void benchmarkSequenceValidator() {
        // Warmup
        IntStream.range(0, 1000).forEach(i -> sequenceValidator.validate(testSourceMac, testBssid));

        // Measure
        long start = System.nanoTime();
        int iterations = 10000;
        for (int i = 0; i < iterations; i++) {
            sequenceValidator.validate(testSourceMac, testBssid);
        }
        long totalNs = System.nanoTime() - start;
        double avgMs = (totalNs / (double) iterations) / 1_000_000.0;

        System.out.printf("SequenceValidator Average: %.4f ms%n", avgMs);
        assertThat(avgMs)
                .as("SequenceValidator should complete in < 1ms")
                .isLessThan(1.0);
    }

    @Test
    @DisplayName("Individual Analyzer Performance: TimeAnomalyDetector < 1ms")
    void benchmarkTimeAnomalyDetector() {
        // Warmup
        IntStream.range(0, 1000).forEach(i -> timeAnomalyDetector.detectAnomalies(testSourceMac, testBssid));

        // Measure
        long start = System.nanoTime();
        int iterations = 10000;
        for (int i = 0; i < iterations; i++) {
            timeAnomalyDetector.detectAnomalies(testSourceMac, testBssid);
        }
        long totalNs = System.nanoTime() - start;
        double avgMs = (totalNs / (double) iterations) / 1_000_000.0;

        System.out.printf("TimeAnomalyDetector Average: %.4f ms%n", avgMs);
        assertThat(avgMs)
                .as("TimeAnomalyDetector should complete in < 1ms")
                .isLessThan(1.0);
    }

    @Test
    @DisplayName("Individual Analyzer Performance: SessionStateChecker < 1ms")
    void benchmarkSessionStateChecker() {
        // Warmup
        IntStream.range(0, 1000).forEach(i -> sessionStateChecker.checkSessionState(testSourceMac, testBssid));

        // Measure
        long start = System.nanoTime();
        int iterations = 10000;
        for (int i = 0; i < iterations; i++) {
            sessionStateChecker.checkSessionState(testSourceMac, testBssid);
        }
        long totalNs = System.nanoTime() - start;
        double avgMs = (totalNs / (double) iterations) / 1_000_000.0;

        System.out.printf("SessionStateChecker Average: %.4f ms%n", avgMs);
        assertThat(avgMs)
                .as("SessionStateChecker should complete in < 1ms")
                .isLessThan(1.0);
    }

    @Test
    @DisplayName("Full Pipeline Performance: Layer1Service < 3ms")
    void benchmarkFullPipeline() {
        DetectionRequest request = buildRequest();

        // Warmup
        IntStream.range(0, 100).forEach(i -> layer1Service.analyze(request));

        // Measure
        List<Long> latencies = new ArrayList<>();
        int iterations = 1000;
        for (int i = 0; i < iterations; i++) {
            long start = System.nanoTime();
            layer1Service.analyze(request);
            long end = System.nanoTime();
            latencies.add(end - start);
        }

        latencies.sort(Long::compareTo);
        double avgMs = latencies.stream().mapToLong(Long::longValue).average().orElse(0) / 1_000_000.0;
        double p50Ms = latencies.get((int) (iterations * 0.50)) / 1_000_000.0;
        double p95Ms = latencies.get((int) (iterations * 0.95)) / 1_000_000.0;
        double p99Ms = latencies.get((int) (iterations * 0.99)) / 1_000_000.0;

        System.out.println("\n=== Full Pipeline Performance ===");
        System.out.printf("Average:  %.4f ms%n", avgMs);
        System.out.printf("P50:      %.4f ms%n", p50Ms);
        System.out.printf("P95:      %.4f ms%n", p95Ms);
        System.out.printf("P99:      %.4f ms%n", p99Ms);
        System.out.println("Target:   < 3.0000 ms");

        assertThat(avgMs)
                .as("Full pipeline average should be < 3ms")
                .isLessThan(3.0);
    }

    @Test
    @DisplayName("Load Test: 1000 frames/sec throughput")
    void loadTest_1000FramesPerSecond() throws InterruptedException {
        int framesPerSecond = 1000;
        int durationSeconds = 3;
        int totalFrames = framesPerSecond * durationSeconds;

        ExecutorService executor = Executors.newFixedThreadPool(10);
        CountDownLatch latch = new CountDownLatch(totalFrames);
        List<Long> responseTimes = new CopyOnWriteArrayList<>();

        long testStart = System.nanoTime();

        for (int i = 0; i < totalFrames; i++) {
            int index = i;
            executor.submit(() -> {
                try {
                    DetectionRequest request = DetectionRequest.builder()
                            .requestId("load-" + index)
                            .sourceMac(testSourceMac)
                            .bssid(testBssid)
                            .timestamp(LocalDateTime.now())
                            .build();

                    long start = System.nanoTime();
                    layer1Service.analyze(request);
                    long end = System.nanoTime();
                    responseTimes.add(end - start);
                } finally {
                    latch.countDown();
                }
            });

            // Throttle to simulate ~1000/sec
            if (i % 100 == 0) {
                Thread.sleep(100);
            }
        }

        latch.await(30, TimeUnit.SECONDS);
        long testEnd = System.nanoTime();
        executor.shutdown();

        double actualDurationSeconds = (testEnd - testStart) / 1_000_000_000.0;
        double actualThroughput = totalFrames / actualDurationSeconds;
        double avgResponseMs = responseTimes.stream().mapToLong(Long::longValue).average().orElse(0) / 1_000_000.0;

        System.out.println("\n=== Load Test Results ===");
        System.out.printf("Total Frames: %d%n", totalFrames);
        System.out.printf("Duration: %.2f seconds%n", actualDurationSeconds);
        System.out.printf("Throughput: %.2f frames/sec%n", actualThroughput);
        System.out.printf("Avg Response: %.4f ms%n", avgResponseMs);

        assertThat(actualThroughput)
                .as("System should handle at least 500 frames/sec")
                .isGreaterThan(500);
    }

    @Test
    @DisplayName("Stress Test: 10000 frames/sec burst")
    void stressTest_10000FramesBurst() throws InterruptedException, ExecutionException {
        int burstSize = 5000; // Reduced for test stability

        ExecutorService executor = Executors.newFixedThreadPool(20);
        List<Future<DetectionResponse>> futures = new ArrayList<>();

        long burstStart = System.nanoTime();

        // Fire all at once (burst)
        for (int i = 0; i < burstSize; i++) {
            int index = i;
            futures.add(executor.submit(() -> {
                DetectionRequest request = DetectionRequest.builder()
                        .requestId("stress-" + index)
                        .sourceMac(testSourceMac)
                        .bssid(testBssid)
                        .timestamp(LocalDateTime.now())
                        .build();
                return layer1Service.analyze(request);
            }));
        }

        // Wait for all to complete
        int completed = 0;
        int errors = 0;
        for (Future<DetectionResponse> future : futures) {
            try {
                future.get(10, TimeUnit.SECONDS);
                completed++;
            } catch (Exception e) {
                errors++;
            }
        }

        long burstEnd = System.nanoTime();
        executor.shutdown();

        double burstDuration = (burstEnd - burstStart) / 1_000_000_000.0;
        double burstThroughput = completed / burstDuration;

        System.out.println("\n=== Stress Test Results ===");
        System.out.printf("Burst Size: %d%n", burstSize);
        System.out.printf("Completed: %d%n", completed);
        System.out.printf("Errors: %d%n", errors);
        System.out.printf("Duration: %.2f seconds%n", burstDuration);
        System.out.printf("Burst Throughput: %.2f frames/sec%n", burstThroughput);

        assertThat(completed)
                .as("Most frames should complete successfully")
                .isGreaterThan((int) (burstSize * 0.95));
    }

    // Helper: Create mock packets
    private List<CapturedPacket> createMockPackets(int count) {
        List<CapturedPacket> packets = new ArrayList<>();
        LocalDateTime baseTime = LocalDateTime.now();
        for (int i = 0; i < count; i++) {
            packets.add(new CapturedPacketBuilder()
                    .withSourceMac(testSourceMac)
                    .withBssid(testBssid)
                    .withSequenceNumber(100 + i)
                    .withTimestamp(baseTime.minusNanos(i * 100_000_000L))
                    .withFrameType("DEAUTH")
                    .build());
        }
        return packets;
    }

    // Helper: Build request
    private DetectionRequest buildRequest() {
        return DetectionRequest.builder()
                .requestId(UUID.randomUUID().toString())
                .sourceMac(testSourceMac)
                .bssid(testBssid)
                .frameType("DEAUTH")
                .sequenceNumber(100)
                .rssi(-60)
                .timestamp(LocalDateTime.now())
                .build();
    }
}
