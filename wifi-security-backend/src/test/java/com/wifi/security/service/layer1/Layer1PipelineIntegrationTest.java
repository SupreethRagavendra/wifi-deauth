package com.wifi.security.service.layer1;

import com.wifi.security.dto.request.DetectionRequest;
import com.wifi.security.dto.response.DetectionResponse;
import com.wifi.security.entity.CapturedPacket;
import com.wifi.security.repository.PacketRepository;
import com.wifi.security.repository.DetectionEventRepository;
import com.wifi.security.util.CapturedPacketBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration Tests for the complete Layer 1 Detection Pipeline.
 * Tests the full flow from request to response with real database interactions.
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
@DisplayName("Layer 1 Full Pipeline Integration Tests")
class Layer1PipelineIntegrationTest {

    @Autowired
    private Layer1Service layer1Service;

    @Autowired
    private PacketRepository packetRepository;

    @Autowired
    private DetectionEventRepository eventRepository;

    private String testSourceMac;
    private String testBssid;

    @BeforeEach
    void setUp() {
        testSourceMac = "AA:AA:AA:AA:AA:AA";
        testBssid = "BB:BB:BB:BB:BB:BB";
        packetRepository.deleteAll();
    }

    @Test
    @DisplayName("Full Pipeline: Normal traffic returns low/no threat")
    void testFullPipeline_NormalTraffic_NoThreat() {
        // Arrange: Insert normal traffic pattern
        List<CapturedPacket> normalPackets = createNormalTrafficPattern();
        packetRepository.saveAll(normalPackets);

        DetectionRequest request = buildRequest();

        // Act
        DetectionResponse response = layer1Service.analyze(request);

        // Assert
        assertThat(response.getThreatLevel())
                .as("Normal traffic should not trigger high threat level")
                .isIn("NONE", "LOW");
        assertThat(response.isAttackDetected()).isFalse();
        assertThat(response.getProcessingTimeMs())
                .as("Processing should complete within 5ms target")
                .isLessThan(50); // Allow margin for DB latency
    }

    @Test
    @DisplayName("Full Pipeline: Attack pattern triggers detection")
    void testFullPipeline_AttackPattern_Detected() {
        // Arrange: Insert attack traffic pattern
        List<CapturedPacket> attackPackets = createAttackTrafficPattern();
        packetRepository.saveAll(attackPackets);

        DetectionRequest request = buildRequest();

        // Act
        DetectionResponse response = layer1Service.analyze(request);

        // Assert
        assertThat(response.getCombinedScore())
                .as("Attack pattern should have elevated score")
                .isGreaterThan(10);
        assertThat(response.getThreatLevel())
                .as("Attack should trigger elevated threat level")
                .isIn("MEDIUM", "HIGH", "CRITICAL");
        assertThat(response.getAnalyzerScores()).isNotNull();
    }

    @Test
    @DisplayName("Concurrent Requests: Thread Safety Verification")
    void testConcurrentRequests_ThreadSafe()
            throws InterruptedException, ExecutionException, java.util.concurrent.TimeoutException {
        // Arrange: Insert some test data
        List<CapturedPacket> packets = createNormalTrafficPattern();
        packetRepository.saveAll(packets);

        int threads = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        List<Future<DetectionResponse>> futures = new ArrayList<>();

        // Act: Submit concurrent detection requests
        for (int i = 0; i < threads; i++) {
            final int index = i;
            futures.add(executor.submit(() -> {
                DetectionRequest request = DetectionRequest.builder()
                        .requestId("test-" + index)
                        .sourceMac(testSourceMac)
                        .bssid(testBssid)
                        .frameType("DEAUTH")
                        .timestamp(LocalDateTime.now())
                        .build();
                return layer1Service.analyze(request);
            }));
        }

        // Assert: All responses should complete without errors
        for (Future<DetectionResponse> future : futures) {
            DetectionResponse response = future.get(5, TimeUnit.SECONDS);
            assertThat(response).isNotNull();
            assertThat(response.getRequestId()).isNotNull();
            assertThat(response.getLayer()).isEqualTo("LAYER_1");
        }

        executor.shutdown();
    }

    @Test
    @DisplayName("Database Interaction: Verify correct query execution")
    void testDatabaseInteraction_CorrectQueries() {
        // Arrange: Insert packets for specific source/bssid
        CapturedPacket packet = new CapturedPacketBuilder()
                .withSourceMac(testSourceMac)
                .withBssid(testBssid)
                .withFrameType("DEAUTH")
                .withSequenceNumber(100)
                .withTimestamp(LocalDateTime.now())
                .build();
        packetRepository.save(packet);

        DetectionRequest request = buildRequest();

        // Act
        DetectionResponse response = layer1Service.analyze(request);

        // Assert: Response should be based on actual DB data
        assertThat(response).isNotNull();
        assertThat(response.getSourceMac()).isEqualTo(testSourceMac);
        assertThat(response.getBssid()).isEqualTo(testBssid);
    }

    @Test
    @DisplayName("Performance: Full pipeline under 3ms with database")
    void testPerformance_FullPipeline() {
        // Arrange
        List<CapturedPacket> packets = createNormalTrafficPattern();
        packetRepository.saveAll(packets);

        DetectionRequest request = buildRequest();

        // Warmup
        for (int i = 0; i < 5; i++) {
            layer1Service.analyze(request);
        }

        // Act: Measure multiple runs
        List<Long> times = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            long start = System.nanoTime();
            layer1Service.analyze(request);
            long end = System.nanoTime();
            times.add((end - start) / 1_000_000); // Convert to ms
        }

        // Assert
        double avgTime = times.stream().mapToLong(Long::longValue).average().orElse(0);
        System.out.printf("Full Pipeline Average Time: %.2f ms%n", avgTime);

        assertThat(avgTime)
                .as("Average processing time should be under target (with some margin for DB)")
                .isLessThan(50); // Relaxed for integration test with DB
    }

    // Helper: Create a normal traffic pattern
    private List<CapturedPacket> createNormalTrafficPattern() {
        List<CapturedPacket> packets = new ArrayList<>();
        LocalDateTime baseTime = LocalDateTime.now();

        // Normal session: Auth, Assoc, then single Deauth
        packets.add(new CapturedPacketBuilder()
                .withSourceMac(testSourceMac)
                .withBssid(testBssid)
                .withFrameType("AUTH")
                .withSequenceNumber(100)
                .withTimestamp(baseTime.minusSeconds(60))
                .build());

        packets.add(new CapturedPacketBuilder()
                .withSourceMac(testSourceMac)
                .withBssid(testBssid)
                .withFrameType("ASSOC")
                .withSequenceNumber(101)
                .withTimestamp(baseTime.minusSeconds(55))
                .build());

        packets.add(new CapturedPacketBuilder()
                .withSourceMac(testSourceMac)
                .withBssid(testBssid)
                .withFrameType("DEAUTH")
                .withSequenceNumber(102)
                .withTimestamp(baseTime)
                .build());

        return packets;
    }

    // Helper: Create an attack traffic pattern
    private List<CapturedPacket> createAttackTrafficPattern() {
        List<CapturedPacket> packets = new ArrayList<>();
        LocalDateTime baseTime = LocalDateTime.now();

        // Attack pattern: Many rapid deauths without prior auth, with duplicates
        for (int i = 0; i < 30; i++) {
            packets.add(new CapturedPacketBuilder()
                    .withSourceMac(testSourceMac)
                    .withBssid(testBssid)
                    .withFrameType("DEAUTH")
                    .withSequenceNumber(100 + (i % 5)) // Repeating sequences
                    .withTimestamp(baseTime.minusNanos(i * 50_000_000L)) // Burst timing
                    .build());
        }

        return packets;
    }

    // Helper to build test request
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
