package com.wifi.security.service.layer1;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import com.wifi.security.repository.PacketRepository;

import java.time.LocalDateTime;
import java.util.Random;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
@DisplayName("Rate Analyzer Accuracy Tests")
public class RateAnalyzerAccuracyTest {

    @Mock
    private PacketRepository packetRepository;

    @InjectMocks
    private RateAnalyzer rateAnalyzer;

    private static final int SCORE_THRESHOLD = 25; // Scores >= 25 are considered Anomalies/Attacks

    @Test
    @DisplayName("Calculate Accuracy, Precision, Recall, F1-Score")
    void calculateAccuracyMetrics() {
        int truePositives = 0;
        int falsePositives = 0;
        int trueNegatives = 0;
        int falseNegatives = 0;

        Random random = new Random();

        System.out.println("Running Accuracy Test on 200 scenarios...");

        // 1. Test 100 Normal Scenarios (0-5 frames)
        // Expectation: Score < 25
        for (int i = 0; i < 100; i++) {
            // Generate random count between 0 and 5 (Normal/Slightly Suspicious)
            long frameCount = random.nextInt(6);

            when(packetRepository.countBySourceMacAndBssidAndTimestampAfter(any(), any(), any()))
                    .thenReturn(frameCount);

            int score = rateAnalyzer.analyzeRate("normal-mac-" + i, "bssid");

            if (score >= SCORE_THRESHOLD) {
                falsePositives++; // Predicted Attack, Actual Normal
            } else {
                trueNegatives++; // Predicted Normal, Actual Normal
            }
        }

        // 2. Test 100 Attack Scenarios (11-100 frames)
        // Expectation: Score >= 25
        for (int i = 0; i < 100; i++) {
            // Generate random count between 11 and 100 (Suspicious/Attack)
            long frameCount = 11 + random.nextInt(90);

            when(packetRepository.countBySourceMacAndBssidAndTimestampAfter(any(), any(), any()))
                    .thenReturn(frameCount);

            int score = rateAnalyzer.analyzeRate("attack-mac-" + i, "bssid");

            if (score >= SCORE_THRESHOLD) {
                truePositives++; // Predicted Attack, Actual Attack
            } else {
                falseNegatives++; // Predicted Normal, Actual Attack
            }
        }

        // Calculate Metrics
        int total = truePositives + trueNegatives + falsePositives + falseNegatives;
        double accuracy = (double) (truePositives + trueNegatives) / total;
        double precision = (truePositives + falsePositives) == 0 ? 0
                : (double) truePositives / (truePositives + falsePositives);
        double recall = (truePositives + falseNegatives) == 0 ? 0
                : (double) truePositives / (truePositives + falseNegatives);
        double f1Score = (precision + recall) == 0 ? 0 : 2 * ((precision * recall) / (precision + recall));

        // Output Confusion Matrix
        System.out.println("\n--- Confusion Matrix ---");
        System.out.printf("                | Predicted Normal | Predicted Attack |%n");
        System.out.printf("Actual Normal   | %-16d | %-16d |%n", trueNegatives, falsePositives);
        System.out.printf("Actual Attack   | %-16d | %-16d |%n", falseNegatives, truePositives);

        System.out.println("\n--- Accuracy Metrics ---");
        System.out.printf("Accuracy:  %.2f%%%n", accuracy * 100);
        System.out.printf("Precision: %.2f%%%n", precision * 100);
        System.out.printf("Recall:    %.2f%%%n", recall * 100);
        System.out.printf("F1-Score:  %.2f%%%n", f1Score * 100);

        // Assertions
        assertThat(accuracy).as("Accuracy should be > 97%").isGreaterThan(0.97);
        assertThat(falsePositives).as("False Positive Rate should be low").isLessThan(5); // < 5% error
    }
}
