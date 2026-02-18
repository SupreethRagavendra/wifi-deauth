package com.wifi.security.performance;

import com.wifi.security.service.layer1.RateAnalyzer;
import com.wifi.security.repository.PacketRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("Rate Analyzer Performance Tests (Simple Benchmark)")
public class RateAnalyzerSimplePerformanceTest {

    @Mock
    private PacketRepository packetRepository;

    @InjectMocks
    private RateAnalyzer rateAnalyzer;

    @Test
    @DisplayName("Benchmark analyzeRate() Performance")
    void benchmarkAnalyzeRate() {
        // Mock Setup
        String sourceMac = "00:11:22:33:44:55";
        String bssid = "AA:BB:CC:DD:EE:FF";

        // Ensure repository returns quickly (simulating idealized DB access or cache)
        when(packetRepository.countBySourceMacAndBssidAndTimestampAfter(eq(sourceMac), eq(bssid),
                any(LocalDateTime.class)))
                .thenReturn(5L);

        // Warmup Phase
        System.out.println("Starting Warmup Phase (1000 iterations)...");
        for (int i = 0; i < 1000; i++) {
            rateAnalyzer.analyzeRate(sourceMac, bssid);
        }
        System.out.println("Warmup Complete.");

        // Measurement Phase
        int iterations = 10000;
        long totalTimeNs = 0;
        List<Long> latencies = new ArrayList<>();

        System.out.println("Starting Measurement Phase (" + iterations + " iterations)...");
        for (int i = 0; i < iterations; i++) {
            long start = System.nanoTime();
            rateAnalyzer.analyzeRate(sourceMac, bssid);
            long end = System.nanoTime();
            long duration = end - start;
            totalTimeNs += duration;
            latencies.add(duration);
        }

        // Calculate Stats
        double avgTimeMs = (totalTimeNs / (double) iterations) / 1_000_000.0;
        latencies.sort(Long::compareTo);
        double p50Ms = latencies.get((int) (iterations * 0.50)) / 1_000_000.0;
        double p95Ms = latencies.get((int) (iterations * 0.95)) / 1_000_000.0;
        double p99Ms = latencies.get((int) (iterations * 0.99)) / 1_000_000.0;

        System.out.println("\n--- Performance Results ---");
        System.out.printf("Average Time: %.4f ms%n", avgTimeMs);
        System.out.printf("P50 Latency:  %.4f ms%n", p50Ms);
        System.out.printf("P95 Latency:  %.4f ms%n", p95Ms);
        System.out.printf("P99 Latency:  %.4f ms%n", p99Ms);
        System.out.println("Target:       < 1.0000 ms");

        // Assertions
        assertThat(avgTimeMs)
                .as("Average execution time should be less than 1ms")
                .isLessThan(1.0);

        assertThat(p99Ms)
                .as("99th percentile execution time should be reasonable (<3ms)")
                .isLessThan(3.0);
    }
}
