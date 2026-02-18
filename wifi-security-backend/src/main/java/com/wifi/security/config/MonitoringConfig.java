package com.wifi.security.config;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.Counter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.wifi.security.service.layer1.Layer1Service;

/**
 * Monitoring Configuration for Detection Engine.
 * Configures Prometheus metrics and custom health indicators.
 */
@Configuration
public class MonitoringConfig {

    @Value("${spring.application.name:wifi-security-backend}")
    private String applicationName;

    /**
     * Custom health indicator for Detection Service.
     */
    @Bean
    public HealthIndicator detectionServiceHealthIndicator(Layer1Service layer1Service) {
        return () -> {
            boolean healthy = layer1Service.isHealthy();
            if (healthy) {
                return Health.up()
                        .withDetail("service", "Layer1Service")
                        .withDetail("status", "operational")
                        .build();
            } else {
                return Health.down()
                        .withDetail("service", "Layer1Service")
                        .withDetail("status", "degraded")
                        .build();
            }
        };
    }

    /**
     * Register custom metrics for detection engine.
     */
    @Bean
    public DetectionMetrics detectionMetrics(MeterRegistry registry) {
        return new DetectionMetrics(registry);
    }

    /**
     * Custom metrics container for detection service.
     */
    public static class DetectionMetrics {

        private final Counter attacksDetectedCounter;
        private final Counter framesAnalyzedCounter;
        private final Timer analysisTimer;
        private final Counter criticalAlertsCounter;
        private final Counter highAlertsCounter;
        private final Counter mediumAlertsCounter;

        public DetectionMetrics(MeterRegistry registry) {
            this.attacksDetectedCounter = Counter.builder("detection.attacks.detected")
                    .description("Total attacks detected")
                    .tag("type", "layer1")
                    .register(registry);

            this.framesAnalyzedCounter = Counter.builder("detection.frames.analyzed")
                    .description("Total frames analyzed")
                    .register(registry);

            this.analysisTimer = Timer.builder("detection.analysis.duration")
                    .description("Frame analysis duration")
                    .publishPercentiles(0.5, 0.95, 0.99)
                    .register(registry);

            this.criticalAlertsCounter = Counter.builder("detection.alerts")
                    .description("Detection alerts by severity")
                    .tag("severity", "critical")
                    .register(registry);

            this.highAlertsCounter = Counter.builder("detection.alerts")
                    .description("Detection alerts by severity")
                    .tag("severity", "high")
                    .register(registry);

            this.mediumAlertsCounter = Counter.builder("detection.alerts")
                    .description("Detection alerts by severity")
                    .tag("severity", "medium")
                    .register(registry);
        }

        public void recordAttackDetected() {
            attacksDetectedCounter.increment();
        }

        public void recordFrameAnalyzed() {
            framesAnalyzedCounter.increment();
        }

        public Timer.Sample startAnalysis() {
            return Timer.start();
        }

        public void stopAnalysis(Timer.Sample sample) {
            sample.stop(analysisTimer);
        }

        public void recordAlert(String severity) {
            switch (severity.toUpperCase()) {
                case "CRITICAL":
                    criticalAlertsCounter.increment();
                    break;
                case "HIGH":
                    highAlertsCounter.increment();
                    break;
                case "MEDIUM":
                    mediumAlertsCounter.increment();
                    break;
            }
        }
    }
}
