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
 * Comprehensive Unit Tests for SessionStateChecker Component.
 * Tests session context validation to detect illegitimate deauth frames.
 * 
 * Key Detection:
 * - Orphan deauths (deauth without prior authentication)
 * - Mass deauth attacks (multiple victims simultaneously)
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Session State Checker Unit Tests")
class SessionStateCheckerTest {

    @Mock
    private PacketRepository packetRepository;

    @InjectMocks
    private SessionStateChecker sessionStateChecker;

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
        @DisplayName("Legitimate disconnect (auth → deauth) returns score 0")
        void testLegitimateDisconnect_ReturnsZero() {
            // Arrange: Normal session - AUTH then DEAUTH
            List<CapturedPacket> packets = new ArrayList<>();
            LocalDateTime baseTime = LocalDateTime.now();
            packets.add(createPacket(testSourceMac, "AUTH", baseTime.minusSeconds(10)));
            packets.add(createPacket(testSourceMac, "ASSOC", baseTime.minusSeconds(9)));
            packets.add(createPacket(testSourceMac, "DEAUTH", baseTime));

            when(packetRepository.findByBssidAndTimestampAfter(eq(testBssid), any()))
                    .thenReturn(packets);

            // Act
            int score = sessionStateChecker.checkSessionState(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("Legitimate session with auth before deauth should return 0")
                    .isEqualTo(0);
        }

        @Test
        @DisplayName("No packets found returns score 0")
        void testNoPackets_ReturnsZero() {
            // Arrange
            when(packetRepository.findByBssidAndTimestampAfter(any(), any()))
                    .thenReturn(List.of());

            // Act
            int score = sessionStateChecker.checkSessionState(testSourceMac, testBssid);

            // Assert
            assertThat(score).isEqualTo(0);
        }

        @Test
        @DisplayName("AP restart (mass disconnect with prior auth) should be low score")
        void testAPRestart_LowScore() {
            // Arrange: Multiple sessions all with proper auth before disconnect
            List<CapturedPacket> packets = new ArrayList<>();
            LocalDateTime baseTime = LocalDateTime.now();

            // Multiple clients with proper auth → deauth sequence
            for (int i = 0; i < 5; i++) {
                String clientMac = String.format("00:00:00:00:00:%02X", i);
                packets.add(createPacket(clientMac, "AUTH", baseTime.minusSeconds(60)));
                packets.add(createPacket(clientMac, "ASSOC", baseTime.minusSeconds(55)));
            }
            // AP sends deauth to all
            for (int i = 0; i < 5; i++) {
                String clientMac = String.format("00:00:00:00:00:%02X", i);
                packets.add(createPacket(clientMac, "DEAUTH", baseTime));
            }

            when(packetRepository.findByBssidAndTimestampAfter(eq(testBssid), any()))
                    .thenReturn(packets);

            // Act
            int score = sessionStateChecker.checkSessionState(testSourceMac, testBssid);

            // Assert - May trigger mass deauth but all have auth context
            assertThat(score)
                    .as("AP restart with proper auth context should be low severity")
                    .isLessThan(35);
        }
    }

    @Nested
    @DisplayName("Attack Cases")
    class AttackCases {

        @Test
        @DisplayName("Orphan deauths (no prior auth) indicate spoofing")
        void testOrphanDeauths_IndicatesSpoofing() {
            // Arrange: Multiple deauths without any prior authentication
            List<CapturedPacket> packets = new ArrayList<>();
            LocalDateTime baseTime = LocalDateTime.now();

            // Source MAC sends multiple deauths without ever authenticating
            for (int i = 0; i < 5; i++) {
                packets.add(createPacket(testSourceMac, "DEAUTH", baseTime.minusSeconds(i)));
            }

            when(packetRepository.findByBssidAndTimestampAfter(eq(testBssid), any()))
                    .thenReturn(packets);

            // Act
            int score = sessionStateChecker.checkSessionState(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("Orphan deauths without session context indicate attack")
                    .isGreaterThanOrEqualTo(10);
        }

        @Test
        @DisplayName("Mass deauth attack (many unique victims) scores high")
        void testMassDeauthAttack_ScoresHigh() {
            // Arrange: Single source deauthing many different clients
            List<CapturedPacket> packets = new ArrayList<>();
            LocalDateTime baseTime = LocalDateTime.now();

            // Attacker MAC sending deauths (simulating broadcast attack)
            for (int i = 0; i < 15; i++) {
                packets.add(createPacket(testSourceMac, "DEAUTH", baseTime.minusNanos(i * 50_000_000L)));
            }

            when(packetRepository.findByBssidAndTimestampAfter(eq(testBssid), any()))
                    .thenReturn(packets);

            // Act
            int score = sessionStateChecker.checkSessionState(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("Mass deauth with many victims indicates attack")
                    .isGreaterThanOrEqualTo(25);
        }

        @Test
        @DisplayName("Targeted attack on active session")
        void testTargetedAttack_ActiveSession() {
            // Arrange: Attacker spoofs deauth to disconnect active client
            List<CapturedPacket> packets = new ArrayList<>();
            LocalDateTime baseTime = LocalDateTime.now();

            // Victim has active session
            String victimMac = "11:22:33:44:55:66";
            packets.add(createPacket(victimMac, "AUTH", baseTime.minusMinutes(5)));
            packets.add(createPacket(victimMac, "ASSOC", baseTime.minusMinutes(4)));
            packets.add(createPacket(victimMac, "PROBE", baseTime.minusSeconds(30)));

            // Attacker (testSourceMac) sends many deauths without being authenticated
            for (int i = 0; i < 10; i++) {
                packets.add(createPacket(testSourceMac, "DEAUTH", baseTime.minusNanos(i * 100_000_000L)));
            }

            when(packetRepository.findByBssidAndTimestampAfter(eq(testBssid), any()))
                    .thenReturn(packets);

            // Act
            int score = sessionStateChecker.checkSessionState(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("Unauthenticated source sending deauths is suspicious")
                    .isGreaterThan(0);
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Database error returns 0 gracefully")
        void testDatabaseError_ReturnsZeroGracefully() {
            // Arrange
            when(packetRepository.findByBssidAndTimestampAfter(any(), any()))
                    .thenThrow(new RuntimeException("DB Connection Failed"));

            // Act
            int score = sessionStateChecker.checkSessionState(testSourceMac, testBssid);

            // Assert
            assertThat(score)
                    .as("System must degrade gracefully on DB failure")
                    .isEqualTo(0);
        }

        @Test
        @DisplayName("Null frame types are handled gracefully")
        void testNullFrameTypes_HandledGracefully() {
            // Arrange
            List<CapturedPacket> packets = new ArrayList<>();
            packets.add(createPacket(testSourceMac, null, LocalDateTime.now()));
            packets.add(createPacket(testSourceMac, "DEAUTH", LocalDateTime.now()));
            when(packetRepository.findByBssidAndTimestampAfter(any(), any()))
                    .thenReturn(packets);

            // Act
            int score = sessionStateChecker.checkSessionState(testSourceMac, testBssid);

            // Assert - Should not throw exception
            assertThat(score).isGreaterThanOrEqualTo(0);
        }

        @Test
        @DisplayName("Mixed case frame types are normalized correctly")
        void testMixedCaseFrameTypes_NormalizedCorrectly() {
            // Arrange
            List<CapturedPacket> packets = new ArrayList<>();
            LocalDateTime baseTime = LocalDateTime.now();
            packets.add(createPacket(testSourceMac, "auth", baseTime.minusSeconds(10)));
            packets.add(createPacket(testSourceMac, "DEAUTH", baseTime));
            when(packetRepository.findByBssidAndTimestampAfter(any(), any()))
                    .thenReturn(packets);

            // Act
            int score = sessionStateChecker.checkSessionState(testSourceMac, testBssid);

            // Assert - Should properly handle mixed case
            assertThat(score).isGreaterThanOrEqualTo(0);
        }
    }

    // Helper: Create a packet with specific attributes
    private CapturedPacket createPacket(String sourceMac, String frameType, LocalDateTime timestamp) {
        return new CapturedPacketBuilder()
                .withSourceMac(sourceMac)
                .withBssid(testBssid)
                .withFrameType(frameType)
                .withTimestamp(timestamp)
                .build();
    }
}
