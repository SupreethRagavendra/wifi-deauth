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
 * Comprehensive Unit Tests for SequenceValidator Component.
 * Tests sequence number pattern analysis for detecting spoofed/injected frames.
 * 
 * Scoring Logic:
 * - SCORE_NORMAL = 0
 * - SCORE_MINOR_ANOMALY = 10
 * - SCORE_SUSPICIOUS = 25
 * - SCORE_ATTACK = 35
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Sequence Validator Unit Tests")
class SequenceValidatorTest {

    @Mock
    private PacketRepository packetRepository;

    @InjectMocks
    private SequenceValidator sequenceValidator;

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
        @DisplayName("Sequential frames return score 0")
        void testSequentialFrames_ReturnsZero() {
            // Arrange: Create packets with sequential sequence numbers
            List<CapturedPacket> packets = createPacketsWithSequences(100, 101, 102, 103, 104);
            when(packetRepository.findRecentPacketsBySourceAndBssid(eq(testSourceMac), eq(testBssid), any()))
                    .thenReturn(packets);

            // Act
            int score = sequenceValidator.validate(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("Sequential sequence numbers should return 0")
                    .isEqualTo(0);
        }

        @Test
        @DisplayName("Insufficient packets (less than 2) returns score 0")
        void testInsufficientPackets_ReturnsZero() {
            // Arrange
            when(packetRepository.findRecentPacketsBySourceAndBssid(any(), any(), any()))
                    .thenReturn(List.of(new CapturedPacketBuilder().build()));

            // Act
            int score = sequenceValidator.validate(testSourceMac, testBssid);

            // Assert
            assertThat(score).isEqualTo(0);
        }

        @Test
        @DisplayName("Client roaming (small gaps) should be tolerated")
        void testClientRoaming_SmallGaps_ReturnsLowScore() {
            // Arrange: Small gaps (up to 10) are normal during roaming
            List<CapturedPacket> packets = createPacketsWithSequences(100, 105, 110, 115);
            when(packetRepository.findRecentPacketsBySourceAndBssid(eq(testSourceMac), eq(testBssid), any()))
                    .thenReturn(packets);

            // Act
            int score = sequenceValidator.validate(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("Small sequence gaps should be tolerated")
                    .isLessThan(25);
        }
    }

    @Nested
    @DisplayName("Attack Cases")
    class AttackCases {

        @Test
        @DisplayName("Duplicate sequence numbers indicate replay attack")
        void testDuplicateSequences_IndicatesReplayAttack() {
            // Arrange: Many duplicates indicate replay attack
            List<CapturedPacket> packets = createPacketsWithSequences(100, 100, 100, 100, 100, 100, 100, 101);
            when(packetRepository.findRecentPacketsBySourceAndBssid(eq(testSourceMac), eq(testBssid), any()))
                    .thenReturn(packets);

            // Act
            int score = sequenceValidator.validate(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("Many duplicate sequences indicate replay attack")
                    .isGreaterThanOrEqualTo(25);
        }

        @Test
        @DisplayName("Sequence reset from high to low indicates spoofing")
        void testSequenceReset_IndicatesSpoofing() {
            // Arrange: Sequence suddenly drops from 3500+ to near 0 (suspicious reset)
            List<CapturedPacket> packets = createPacketsWithSequences(3500, 3501, 50, 51, 3600, 60);
            when(packetRepository.findRecentPacketsBySourceAndBssid(eq(testSourceMac), eq(testBssid), any()))
                    .thenReturn(packets);

            // Act
            int score = sequenceValidator.validate(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("Sequence resets from high to low indicate spoofing")
                    .isGreaterThanOrEqualTo(25);
        }

        @Test
        @DisplayName("Large abnormal gaps indicate injection attack")
        void testLargeAbnormalGaps_IndicatesInjection() {
            // Arrange: Gaps > 10 but < 4000 (not wraparound)
            List<CapturedPacket> packets = createPacketsWithSequences(100, 500, 1000, 1500, 2000, 2500);
            when(packetRepository.findRecentPacketsBySourceAndBssid(eq(testSourceMac), eq(testBssid), any()))
                    .thenReturn(packets);

            // Act
            int score = sequenceValidator.validate(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("Large gaps indicate frame injection")
                    .isGreaterThan(0);
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Sequence wraparound (4095 → 0) should NOT trigger false positive")
        void testSequenceWraparound_NotFalsePositive() {
            // Arrange: Normal wraparound from 4095 to 0
            List<CapturedPacket> packets = createPacketsWithSequences(4090, 4091, 4092, 4093, 4094, 4095, 0, 1, 2);
            when(packetRepository.findRecentPacketsBySourceAndBssid(eq(testSourceMac), eq(testBssid), any()))
                    .thenReturn(packets);

            // Act
            int score = sequenceValidator.validate(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("Normal wraparound at 4095→0 should not trigger attack detection")
                    .isLessThanOrEqualTo(10); // Allow minor anomaly but not suspicious
        }

        @Test
        @DisplayName("Database error returns 0 gracefully")
        void testDatabaseError_ReturnsZeroGracefully() {
            // Arrange
            when(packetRepository.findRecentPacketsBySourceAndBssid(any(), any(), any()))
                    .thenThrow(new RuntimeException("DB Connection Failed"));

            // Act
            int score = sequenceValidator.validate(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("System must degrade gracefully on DB failure")
                    .isEqualTo(0);
        }

        @Test
        @DisplayName("Null sequence numbers are handled gracefully")
        void testNullSequenceNumbers_HandledGracefully() {
            // Arrange
            List<CapturedPacket> packets = new ArrayList<>();
            packets.add(new CapturedPacketBuilder().withSequenceNumber(null).build());
            packets.add(new CapturedPacketBuilder().withSequenceNumber(100).build());
            packets.add(new CapturedPacketBuilder().withSequenceNumber(null).build());
            when(packetRepository.findRecentPacketsBySourceAndBssid(any(), any(), any()))
                    .thenReturn(packets);

            // Act
            int score = sequenceValidator.validate(testSourceMac, testBssid);

            // Assert - Should not throw exception
            assertThat(score).isGreaterThanOrEqualTo(0);
        }
    }

    // Helper method to create packets with specific sequence numbers
    private List<CapturedPacket> createPacketsWithSequences(int... sequences) {
        List<CapturedPacket> packets = new ArrayList<>();
        LocalDateTime baseTime = LocalDateTime.now();
        int index = 0;
        for (int seq : sequences) {
            packets.add(new CapturedPacketBuilder()
                    .withSourceMac(testSourceMac)
                    .withBssid(testBssid)
                    .withSequenceNumber(seq)
                    .withTimestamp(baseTime.plusNanos(index * 100_000_000L))
                    .build());
            index++;
        }
        return packets;
    }
}
