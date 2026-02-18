package com.wifi.security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Async Configuration for Detection Engine.
 * Configures thread pools for parallel analyzer execution.
 */
@Configuration
public class AsyncConfig {

    @Value("${detection.async.core-pool-size:4}")
    private int corePoolSize;

    @Value("${detection.async.max-pool-size:8}")
    private int maxPoolSize;

    /**
     * Dedicated executor for Layer 1 analyzers.
     * Uses a fixed thread pool to control parallelism and resource usage.
     */
    @Bean(name = "layer1Executor")
    public ExecutorService layer1Executor() {
        return Executors.newFixedThreadPool(corePoolSize, new ThreadFactory() {
            private final AtomicInteger counter = new AtomicInteger(0);

            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r);
                t.setName("layer1-analyzer-" + counter.getAndIncrement());
                t.setDaemon(true);
                t.setPriority(Thread.NORM_PRIORITY + 1); // Slightly higher priority
                return t;
            }
        });
    }

    /**
     * General purpose async executor for batch processing.
     */
    @Bean(name = "batchExecutor")
    public ExecutorService batchExecutor() {
        return Executors.newFixedThreadPool(maxPoolSize, new ThreadFactory() {
            private final AtomicInteger counter = new AtomicInteger(0);

            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r);
                t.setName("batch-processor-" + counter.getAndIncrement());
                t.setDaemon(true);
                return t;
            }
        });
    }
}
