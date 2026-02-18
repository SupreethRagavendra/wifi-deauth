package com.wifi.security.service.layer1;

import com.wifi.security.repository.PacketRepository;
import com.wifi.security.util.CapturedPacketBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("Rate Analyzer Unit Tests")
class RateAnalyzerTest {

    @Mock
    private PacketRepository packetRepository;

    @InjectMocks
    private RateAnalyzer rateAnalyzer;

    private String testSourceMac;
    private String testBssid;

    @BeforeEach
    void setUp() {
        testSourceMac = "00:11:22:33:44:55";
        testBssid = "AA:BB:CC:DD:EE:FF";
    }

    @Test
    @DisplayName("Test Normal Disconnect: Single frame should return score 0")
    void testNormalDisconnect_SingleFrame_ReturnsZero() {
        // Arrange
        when(packetRepository.countBySourceMacAndBssidAndTimestampAfter(eq(testSourceMac), eq(testBssid),
                any(LocalDateTime.class)))
                .thenReturn(1L);

        // Act
        int score = rateAnalyzer.analyzeRate(testSourceMac, testBssid);

        // Assert
        assertThat(score)
                .as("Single frame is normal behavior")
                .isEqualTo(0);
    }

    @Test
    @DisplayName("Test Mild Activity: Three frames should return score 10")
    void testMildActivity_ThreeFrames_ReturnsTen() {
        // Arrange
        when(packetRepository.countBySourceMacAndBssidAndTimestampAfter(eq(testSourceMac), eq(testBssid),
                any(LocalDateTime.class)))
                .thenReturn(3L);

        // Act
        int score = rateAnalyzer.analyzeRate(testSourceMac, testBssid);

        // Assert
        assertThat(score)
                .as("3 frames indicate mild suspicion")
                .isEqualTo(10);
    }

    @Test
    @DisplayName("Test Suspicious Activity: Eight frames should return score 25")
    void testSuspiciousActivity_EightFrames_ReturnsTwentyFive() {
        // Arrange
        when(packetRepository.countBySourceMacAndBssidAndTimestampAfter(eq(testSourceMac), eq(testBssid),
                any(LocalDateTime.class)))
                .thenReturn(8L);

        // Act
        int score = rateAnalyzer.analyzeRate(testSourceMac, testBssid);

        // Assert
        assertThat(score)
                .as("8 frames within short window is highly suspicious")
                .isEqualTo(25);
    }

    @Test
    @DisplayName("Test Attack Pattern: Fifty frames should return score 35 (Attack)")
    void testAttackPattern_FiftyFrames_ReturnsThirtyFive() {
        // Arrange
        when(packetRepository.countBySourceMacAndBssidAndTimestampAfter(eq(testSourceMac), eq(testBssid),
                any(LocalDateTime.class)))
                .thenReturn(50L);

        // Act
        int score = rateAnalyzer.analyzeRate(testSourceMac, testBssid);

        // Assert
        assertThat(score)
                .as("50 frames indicate a definite attack")
                .isEqualTo(35);
    }

    @Test
    @DisplayName("Test Database Error: Should return 0 gracefully")
    void testDatabaseError_ReturnsZeroGracefully() {
        // Arrange
        when(packetRepository.countBySourceMacAndBssidAndTimestampAfter(any(), any(), any()))
                .thenThrow(new RuntimeException("DB Connection Failed"));

        // Act
        int score = rateAnalyzer.analyzeRate(testSourceMac, testBssid);

        // Assert
        assertThat(score)
                .as("System must degrade gracefully on DB failure")
                .isEqualTo(0);
    }
}
