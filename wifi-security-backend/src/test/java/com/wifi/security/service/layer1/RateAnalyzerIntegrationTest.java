package com.wifi.security.service.layer1;

import com.wifi.security.entity.CapturedPacket;
import com.wifi.security.repository.PacketRepository;
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
import java.util.concurrent.*;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
@DisplayName("Rate Analyzer Integration Tests")
class RateAnalyzerIntegrationTest {

    @Autowired
    private RateAnalyzer rateAnalyzer;

    @Autowired
    private PacketRepository packetRepository;

    private String testSourceMac;
    private String testBssid;

    @BeforeEach
    void setUp() {
        testSourceMac = "11:11:11:11:11:11";
        testBssid = "22:22:22:22:22:22";
        // Clear repo is handled by Transactional rollback usually, but to be safe
        packetRepository.deleteAll();
    }

    @Test
    @DisplayName("Test Rate Analyzer with Real Database: Accurate Scoring")
    void testRateAnalyzer_WithRealDatabase_AccurateScoring() {
        // Arrange: Insert 6 packets (should trigger slightly suspicious - threshold >
        // 5)
        // Adjusting to thresholds: <=2 normal, <=5 slightly suspicious (10), <=10
        // suspicious (25), >10 attack (35)

        // Let's insert 6 packets. 6 > 5 so it should be Suspicious (Score 25) based on
        // logic:
        // <= 5 is 10.
        // <= 10 is 25.
        // So 6 is <= 10, thus score 25.

        List<CapturedPacket> packets = new ArrayList<>();
        CapturedPacketBuilder builder = new CapturedPacketBuilder()
                .withSourceMac(testSourceMac)
                .withBssid(testBssid)
                .withFrameType("Deauth");

        for (int i = 0; i < 6; i++) {
            packets.add(builder
                    .withSequenceNumber(i)
                    .withTimestamp(LocalDateTime.now().minusSeconds(1)) // Recent
                    .build());
        }
        packetRepository.saveAll(packets);

        // Act
        int score = rateAnalyzer.analyzeRate(testSourceMac, testBssid);

        // Assert
        assertThat(score)
                .as("6 packets should fall into Suspicious bucket (Target > 5 and <= 10)")
                .isEqualTo(25);
    }

    @Test
    @DisplayName("Test Concurrent Requests: Ensure Thread Safety")
    void testConcurrentRequests_ThreadSafe() throws InterruptedException, ExecutionException {
        // Arrange
        // Insert enough packets for 'Attack' score in DB
        CapturedPacketBuilder builder = new CapturedPacketBuilder()
                .withSourceMac(testSourceMac)
                .withBssid(testBssid);

        List<CapturedPacket> packets = new ArrayList<>();
        // Insert 15 packets -> Attack Score 35
        for (int i = 0; i < 15; i++) {
            packets.add(builder.withSequenceNumber(i).withTimestamp(LocalDateTime.now()).build());
        }
        packetRepository.saveAll(packets);

        int threads = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        List<Future<Integer>> futures = new ArrayList<>();

        // Act
        for (int i = 0; i < threads; i++) {
            futures.add(executor.submit(() -> rateAnalyzer.analyzeRate(testSourceMac, testBssid)));
        }

        // Assert
        for (Future<Integer> future : futures) {
            int score = future.get();
            assertThat(score).isEqualTo(35);
        }

        executor.shutdown();
    }
}
