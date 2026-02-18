package com.wifi.security.performance;

import com.wifi.security.service.layer1.RateAnalyzer;
import com.wifi.security.repository.PacketRepository;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, warmups = 1)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 10, time = 1)
public class RateAnalyzerBenchmark {

    private ConfigurableApplicationContext context;
    private RateAnalyzer rateAnalyzer;
    private PacketRepository packetRepository; // We might need to mock this or use a real one

    // To make this a true unit benchmark, we should mock the repository to avoid DB
    // latency
    // However, if the goal is to test the full component including DB query (which
    // is likely given the context of <3ms),
    // we need the Spring Context.

    @Setup(Level.Trial)
    public void setup() {
        // Option A: Mock the repository manually for pure logic benchmark
        // This is faster and tests the logic overhead
        /*
         * packetRepository = mock(PacketRepository.class);
         * when(packetRepository.countBySourceMacAndBssidAndTimestampAfter(any(), any(),
         * any()))
         * .thenReturn(5L);
         * rateAnalyzer = new RateAnalyzer(packetRepository);
         */

        // Option B: Load Spring Context (Heavier, includes DB latency)
        // Usually JMH with Spring Boot is tricky. For this example, we'll simulate the
        // component logic
        // or assume the context is available.
        // A common pattern is to start the context in Setup.

        try {
            // Adjust to your main application class
            // context = SpringApplication.run(WifiSecurityBackendApplication.class);
            // rateAnalyzer = context.getBean(RateAnalyzer.class);
        } catch (Exception e) {
            System.err.println("Failed to start Spring context for benchmark: " + e.getMessage());
        }
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        if (context != null) {
            context.close();
        }
    }

    @Benchmark
    public void benchmarkAnalyzeRate(Blackhole bh) {
        // In a real benchmark, we'd want to use the repository.
        // If mocking, we test method overhead.

        // Since I cannot easily set up the full Spring Context and JMH here without
        // more config,
        // I will illustrate what the benchmark method looks like.

        // Simulating the call
        // int score = rateAnalyzer.analyzeRate("00:11:22:33:44:55",
        // "AA:BB:CC:DD:EE:FF");
        // bh.consume(score);
    }
}
