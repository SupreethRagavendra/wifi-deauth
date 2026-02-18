package com.wifi.security.service.layer1;

import com.wifi.security.entity.CapturedPacket;
import com.wifi.security.repository.PacketRepository;
import com.wifi.security.util.CapturedPacketBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Comprehensive Unit Tests for TimeAnomalyDetector Component.
 * Tests temporal pattern analysis to detect automated attack tools.
 * 
 * Key Detection:
 * - Burst patterns (many frames in milliseconds)
 * - Very low timing variance (machine-generated traffic)
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Time Anomaly Detector Unit Tests")
class TimeAnomalyDetectorTest {

    @Mock
    private PacketRepository packetRepository;

    @InjectMocks
    private TimeAnomalyDetector timeAnomalyDetector;

    private String testSourceMac;
    private String testBssid;

    @BeforeEach
    void setUp() {
        testSourceMac = "00:11:22:33:44:55";
        testBssid = "AA:BB:CC:DD:EE:FF";
    }

    @Nested
    @DisplayName("Normal Cases")
    class NormalCases {

        @Test
        @DisplayName("Irregular timing (human-like) returns score 0")
        void testIrregularTiming_ReturnsZero() {
            // Arrange: Variable timing intervals (100ms, 500ms, 200ms, 800ms)
            List<CapturedPacket> packets = createPacketsWithIntervals(0, 100, 600, 800, 1600);
            when(packetRepository.findRecentPacketsBySourceAndBssid(eq(testSourceMac), eq(testBssid), any()))
                    .thenReturn(packets);

            // Act
            int score = timeAnomalyDetector.detectAnomalies(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("Irregular timing indicates human behavior")
                    .isEqualTo(0);
        }

        @Test
        @DisplayName("Insufficient packets returns score 0")
        void testInsufficientPackets_ReturnsZero() {
            // Arrange: Less than 3 packets
            when(packetRepository.findRecentPacketsBySourceAndBssid(any(), any(), any()))
                    .thenReturn(List.of(
                            new CapturedPacketBuilder().build(),
                            new CapturedPacketBuilder().build()));

            // Act
            int score = timeAnomalyDetector.detectAnomalies(testSourceMac, testBssid);

            // Assert
            assertThat(score).isEqualTo(0);
        }
    }

    @Nested
    @DisplayName("Attack Cases")
    class AttackCases {

        @Test
        @DisplayName("Burst traffic (5+ frames within 10ms) indicates attack")
        void testBurstTraffic_IndicatesAttack() {
            // Arrange: Many frames within 10ms intervals = burst
            List<CapturedPacket> packets = createPacketsWithIntervals(0, 2, 4, 6, 8, 10, 12, 14);
            when(packetRepository.findRecentPacketsBySourceAndBssid(eq(testSourceMac), eq(testBssid), any()))
                    .thenReturn(packets);

            // Act
            int score = timeAnomalyDetector.detectAnomalies(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("Burst traffic indicates automated attack tool")
                    .isGreaterThanOrEqualTo(10);
        }

        @Test
        @DisplayName("Precise machine-like timing (low variance) indicates automation")
        void testMachineLikeTiming_IndicatesAutomation() {
            // Arrange: Very consistent intervals (e.g., exactly 50ms apart)
            List<CapturedPacket> packets = createPacketsWithExactIntervals(50, 10);
            when(packetRepository.findRecentPacketsBySourceAndBssid(eq(testSourceMac), eq(testBssid), any()))
                    .thenReturn(packets);

            // Act
            int score = timeAnomalyDetector.detectAnomalies(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("Precise timing with low variance indicates machine-generated traffic")
                    .isGreaterThanOrEqualTo(25);
        }

        @Test
        @DisplayName("Deauth flood pattern (50 frames/sec burst)")
        void testDeauthFloodPattern() {
            // Arrange: Simulate 50 frames in 1 second with burst patterns
            List<CapturedPacket> packets = new ArrayList<>();
            LocalDateTime baseTime = LocalDateTime.now();
            for (int i = 0; i < 50; i++) {
                packets.add(new CapturedPacketBuilder()
                        .withSourceMac(testSourceMac)
                        .withBssid(testBssid)
                        .withTimestamp(baseTime.plusNanos(i * 5_000_000L)) // 5ms apart = burst
                        .build());
            }
            when(packetRepository.findRecentPacketsBySourceAndBssid(eq(testSourceMac), eq(testBssid), any()))
                    .thenReturn(packets);

            // Act
            int score = timeAnomalyDetector.detectAnomalies(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("Flood pattern should trigger attack score")
                    .isGreaterThanOrEqualTo(25);
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Database error returns 0 gracefully")
        void testDatabaseError_ReturnsZeroGracefully() {
            // Arrange
            when(packetRepository.findRecentPacketsBySourceAndBssid(any(), any(), any()))
                    .thenThrow(new RuntimeException("DB Connection Failed"));

            // Act
            int score = timeAnomalyDetector.detectAnomalies(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("System must degrade gracefully on DB failure")
                    .isEqualTo(0);
        }

        @Test
        @DisplayName("Null timestamps are handled gracefully")
        void testNullTimestamps_HandledGracefully() {
            // Arrange
            List<CapturedPacket> packets = new ArrayList<>();
            packets.add(new CapturedPacketBuilder().withTimestamp(null).build());
            packets.add(new CapturedPacketBuilder().withTimestamp(LocalDateTime.now()).build());
            packets.add(new CapturedPacketBuilder().withTimestamp(null).build());
            packets.add(new CapturedPacketBuilder().withTimestamp(LocalDateTime.now()).build());
            when(packetRepository.findRecentPacketsBySourceAndBssid(any(), any(), any()))
                    .thenReturn(packets);

            // Act
            int score = timeAnomalyDetector.detectAnomalies(testSourceMac, testBssid);

            // Assert - Should not throw exception
            assertThat(score).isGreaterThanOrEqualTo(0);
        }
    }

    // Helper: Create packets with specific millisecond intervals from base time
    private List<CapturedPacket> createPacketsWithIntervals(int... offsetsMs) {
        List<CapturedPacket> packets = new ArrayList<>();
        LocalDateTime baseTime = LocalDateTime.now().minusSeconds(5);
        for (int offsetMs : offsetsMs) {
            packets.add(new CapturedPacketBuilder()
                    .withSourceMac(testSourceMac)
                    .withBssid(testBssid)
                    .withTimestamp(baseTime.plusNanos(offsetMs * 1_000_000L))
                    .build());
        }
        return packets;
    }

    // Helper: Create packets with exact intervals (for low variance simulation)
    private List<CapturedPacket> createPacketsWithExactIntervals(int intervalMs, int count) {
        List<CapturedPacket> packets = new ArrayList<>();
        LocalDateTime baseTime = LocalDateTime.now().minusSeconds(5);
        for (int i = 0; i < count; i++) {
            packets.add(new CapturedPacketBuilder()
                    .withSourceMac(testSourceMac)
                    .withBssid(testBssid)
                    .withTimestamp(baseTime.plusNanos(i * intervalMs * 1_000_000L))
                    .build());
        }
        return packets;
    }
}
