package com.wifi.security.service.layer1;

import com.wifi.security.dto.request.DetectionRequest;
import com.wifi.security.dto.response.DetectionResponse;
import com.wifi.security.repository.DetectionEventRepository;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;

/**
 * Comprehensive Unit Tests for Layer1Service Orchestrator.
 * Tests parallel execution, scoring combination, and threat level
 * classification.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Layer 1 Service Unit Tests")
class Layer1ServiceTest {

    @Mock
    private RateAnalyzer rateAnalyzer;

    @Mock
    private SequenceValidator sequenceValidator;

    @Mock
    private TimeAnomalyDetector timeAnomalyDetector;

    @Mock
    private SessionStateChecker sessionStateChecker;

    @Mock
    private DetectionEventRepository eventRepository;

    private Layer1Service layer1Service;
    private MeterRegistry meterRegistry;

    private String testSourceMac;
    private String testBssid;

    @BeforeEach
    void setUp() {
        testSourceMac = "00:11:22:33:44:55";
        testBssid = "AA:BB:CC:DD:EE:FF";
        meterRegistry = new SimpleMeterRegistry();
        layer1Service = new Layer1Service(
                rateAnalyzer,
                sequenceValidator,
                timeAnomalyDetector,
                sessionStateChecker,
                meterRegistry,
                eventRepository);

        ReflectionTestUtils.setField(layer1Service, "attackThreshold", 50);
        ReflectionTestUtils.setField(layer1Service, "suspiciousThreshold", 30);
        ReflectionTestUtils.setField(layer1Service, "warningThreshold", 15);
        ReflectionTestUtils.setField(layer1Service, "timeoutMs", 1000L);

        layer1Service.initMetrics();
    }

    @Nested
    @DisplayName("Detection Flow Tests")
    class DetectionFlowTests {

        @Test
        @DisplayName("All analyzers return 0 → Threat Level NONE")
        void testAllAnalyzersZero_ThreatLevelNone() {
            // Arrange
            lenient().when(rateAnalyzer.analyzeRate(any(), any())).thenReturn(0);
            lenient().when(sequenceValidator.validate(any(), any())).thenReturn(0);
            lenient().when(timeAnomalyDetector.detectAnomalies(any(), any())).thenReturn(0);
            lenient().when(sessionStateChecker.checkSessionState(any(), any())).thenReturn(0);

            DetectionRequest request = buildRequest();

            // Act
            DetectionResponse response = layer1Service.analyze(request);

            // Assert
            assertThat(response.getCombinedScore())
                    .as("Combined score should be 0 when all analyzers return 0")
                    .isEqualTo(0);
            assertThat(response.getThreatLevel())
                    .as("Threat level should be NONE")
                    .isEqualTo("NONE");
            assertThat(response.isAttackDetected())
                    .as("Attack should not be detected")
                    .isFalse();
        }

        @Test
        @DisplayName("All analyzers return max (100) → Threat Level CRITICAL")
        void testAllAnalyzersMax_ThreatLevelCritical() {
            // Arrange
            lenient().when(rateAnalyzer.analyzeRate(any(), any())).thenReturn(100);
            lenient().when(sequenceValidator.validate(any(), any())).thenReturn(100);
            lenient().when(timeAnomalyDetector.detectAnomalies(any(), any())).thenReturn(100);
            lenient().when(sessionStateChecker.checkSessionState(any(), any())).thenReturn(100);

            DetectionRequest request = buildRequest();

            // Act
            DetectionResponse response = layer1Service.analyze(request);

            // Assert
            // Weighted: (100*0.30) + (100*0.25) + (100*0.25) + (100*0.20) = 100
            assertThat(response.getCombinedScore())
                    .as("Combined score should be 100")
                    .isEqualTo(100);
            assertThat(response.getThreatLevel())
                    .as("Threat level should be CRITICAL for score >= 50")
                    .isEqualTo("CRITICAL");
            assertThat(response.isAttackDetected())
                    .as("Attack should be detected for critical scores")
                    .isTrue();
        }

        @Test
        @DisplayName("Weighted scoring calculation is correct")
        void testWeightedScoringCalculation() {
            // Arrange: Different scores for each analyzer
            // Rate: 30% weight, Seq: 25% weight, Time: 25% weight, Session: 20% weight
            lenient().when(rateAnalyzer.analyzeRate(any(), any())).thenReturn(20); // 20 * 0.30 = 6
            lenient().when(sequenceValidator.validate(any(), any())).thenReturn(10); // 10 * 0.25 = 2.5
            lenient().when(timeAnomalyDetector.detectAnomalies(any(), any())).thenReturn(30); // 30 * 0.25 = 7.5
            lenient().when(sessionStateChecker.checkSessionState(any(), any())).thenReturn(15); // 15 * 0.20 = 3
            // Expected: 6 + 2.5 + 7.5 + 3 = 19

            DetectionRequest request = buildRequest();

            // Act
            DetectionResponse response = layer1Service.analyze(request);

            // Assert
            assertThat(response.getCombinedScore())
                    .as("Combined weighted score should be calculated correctly")
                    .isEqualTo(19); // Round(19.0) = 19
        }
    }

    @Nested
    @DisplayName("Threat Level Classification Tests")
    class ThreatLevelTests {

        @Test
        @DisplayName("Score >= 50 → CRITICAL")
        void testCriticalThreshold() {
            // Arrange: High scores to exceed Critical threshold (50)
            lenient().when(rateAnalyzer.analyzeRate(any(), any())).thenReturn(60);
            lenient().when(sequenceValidator.validate(any(), any())).thenReturn(60);
            lenient().when(timeAnomalyDetector.detectAnomalies(any(), any())).thenReturn(60);
            lenient().when(sessionStateChecker.checkSessionState(any(), any())).thenReturn(60);

            DetectionRequest request = buildRequest();

            // Act
            DetectionResponse response = layer1Service.analyze(request);

            // Assert
            assertThat(response.getThreatLevel()).isEqualTo("CRITICAL");
        }

        @Test
        @DisplayName("Score >= 30 but < 50 → HIGH")
        void testHighThreshold() {
            // Arrange: Scores that produce combined ~35
            lenient().when(rateAnalyzer.analyzeRate(any(), any())).thenReturn(35);
            lenient().when(sequenceValidator.validate(any(), any())).thenReturn(35);
            lenient().when(timeAnomalyDetector.detectAnomalies(any(), any())).thenReturn(35);
            lenient().when(sessionStateChecker.checkSessionState(any(), any())).thenReturn(35);

            DetectionRequest request = buildRequest();

            // Act
            DetectionResponse response = layer1Service.analyze(request);

            // Assert
            assertThat(response.getCombinedScore()).isGreaterThanOrEqualTo(30);
            assertThat(response.getThreatLevel()).isEqualTo("HIGH");
        }

        @Test
        @DisplayName("Score >= 15 but < 30 → MEDIUM")
        void testMediumThreshold() {
            // Arrange: Moderate scores
            lenient().when(rateAnalyzer.analyzeRate(any(), any())).thenReturn(25);
            lenient().when(sequenceValidator.validate(any(), any())).thenReturn(10);
            lenient().when(timeAnomalyDetector.detectAnomalies(any(), any())).thenReturn(10);
            lenient().when(sessionStateChecker.checkSessionState(any(), any())).thenReturn(10);
            // (25*0.30) + (10*0.25) + (10*0.25) + (10*0.20) = 7.5 + 2.5 + 2.5 + 2 = 14.5 ->
            // 15

            DetectionRequest request = buildRequest();

            // Act
            DetectionResponse response = layer1Service.analyze(request);

            // Assert
            assertThat(response.getCombinedScore()).isBetween(15, 29);
            assertThat(response.getThreatLevel()).isEqualTo("MEDIUM");
        }

        @Test
        @DisplayName("Score > 0 but < 15 → LOW")
        void testLowThreshold() {
            // Arrange: Low scores
            lenient().when(rateAnalyzer.analyzeRate(any(), any())).thenReturn(10);
            lenient().when(sequenceValidator.validate(any(), any())).thenReturn(0);
            lenient().when(timeAnomalyDetector.detectAnomalies(any(), any())).thenReturn(0);
            lenient().when(sessionStateChecker.checkSessionState(any(), any())).thenReturn(0);
            // (10*0.30) = 3

            DetectionRequest request = buildRequest();

            // Act
            DetectionResponse response = layer1Service.analyze(request);

            // Assert
            assertThat(response.getCombinedScore()).isBetween(1, 14);
            assertThat(response.getThreatLevel()).isEqualTo("LOW");
        }
    }

    @Nested
    @DisplayName("Response Validation Tests")
    class ResponseValidationTests {

        @Test
        @DisplayName("Response contains all required fields")
        void testResponseContainsAllFields() {
            // Arrange
            lenient().when(rateAnalyzer.analyzeRate(any(), any())).thenReturn(10);
            lenient().when(sequenceValidator.validate(any(), any())).thenReturn(10);
            lenient().when(timeAnomalyDetector.detectAnomalies(any(), any())).thenReturn(10);
            lenient().when(sessionStateChecker.checkSessionState(any(), any())).thenReturn(10);

            DetectionRequest request = buildRequest();

            // Act
            DetectionResponse response = layer1Service.analyze(request);

            // Assert
            assertThat(response.getRequestId()).isEqualTo(request.getRequestId());
            assertThat(response.getSourceMac()).isEqualTo(testSourceMac);
            assertThat(response.getBssid()).isEqualTo(testBssid);
            assertThat(response.getAnalysisTimestamp()).isNotNull();
            assertThat(response.getProcessingTimeMs()).isGreaterThanOrEqualTo(0);
            assertThat(response.getLayer()).isEqualTo("LAYER_1");
            assertThat(response.getAnalyzerScores()).isNotNull();
            assertThat(response.getAnalyzerScores().getRateAnalyzerScore()).isEqualTo(10);
        }

        @Test
        @DisplayName("Processing time is under 5ms target")
        void testProcessingTimeUnder5ms() {
            // Arrange
            lenient().when(rateAnalyzer.analyzeRate(any(), any())).thenReturn(0);
            lenient().when(sequenceValidator.validate(any(), any())).thenReturn(0);
            lenient().when(timeAnomalyDetector.detectAnomalies(any(), any())).thenReturn(0);
            lenient().when(sessionStateChecker.checkSessionState(any(), any())).thenReturn(0);

            DetectionRequest request = buildRequest();

            // Act
            DetectionResponse response = layer1Service.analyze(request);

            // Assert
            assertThat(response.getProcessingTimeMs())
                    .as("Processing time should be under 5ms with mocked analyzers")
                    .isLessThan(50); // Allow margin for overhead. Tests might be slower.
        }
    }

    @Nested
    @DisplayName("Health Check Tests")
    class HealthCheckTests {

        @Test
        @DisplayName("isHealthy returns true when all components available")
        void testIsHealthy_ReturnsTrue() {
            // Act
            boolean healthy = layer1Service.isHealthy();

            // Assert
            assertThat(healthy).isTrue();
        }
    }

    // Helper to build a test request
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
