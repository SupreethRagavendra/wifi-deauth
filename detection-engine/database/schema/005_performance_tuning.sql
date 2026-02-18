-- ====================================================================
-- WiFi Deauth Attack Detection System - Performance Tuning
-- MySQL 8.0+ Required
-- ====================================================================
-- Connection pooling, caching, and server configuration recommendations
-- ====================================================================

-- ====================================================================
-- SECTION 1: MYSQL SERVER CONFIGURATION (my.cnf / my.ini)
-- ====================================================================
/*
Add these settings to your MySQL configuration file:

[mysqld]
# ================================================================
# INNODB BUFFER POOL SETTINGS
# ================================================================
# Set to 70-80% of available RAM for dedicated DB server
# For 32GB RAM server, use ~24GB
innodb_buffer_pool_size = 24G

# Use multiple buffer pool instances (1 per GB, max 64)
innodb_buffer_pool_instances = 24

# Pre-warm buffer pool on restart
innodb_buffer_pool_dump_at_shutdown = ON
innodb_buffer_pool_load_at_startup = ON

# ================================================================
# INNODB LOG SETTINGS (Critical for write performance)
# ================================================================
# Large redo log for high write throughput
innodb_log_file_size = 2G
innodb_log_buffer_size = 256M
innodb_log_files_in_group = 2

# Flush behavior (1=safest, 2=fast with battery-backed cache)
innodb_flush_log_at_trx_commit = 2

# Use O_DIRECT to bypass OS cache
innodb_flush_method = O_DIRECT

# ================================================================
# INNODB I/O SETTINGS
# ================================================================
# For NVMe SSD, increase IO capacity
innodb_io_capacity = 10000
innodb_io_capacity_max = 20000

# Read-ahead settings
innodb_read_ahead_threshold = 0
innodb_random_read_ahead = OFF

# Thread concurrency (0 = auto)
innodb_thread_concurrency = 0

# ================================================================
# CONNECTION HANDLING
# ================================================================
# Max connections (match your connection pool * app instances + overhead)
max_connections = 500

# Thread pool for connection handling
thread_handling = pool-of-threads
thread_pool_size = 16
thread_pool_max_threads = 500

# Connection timeout
wait_timeout = 600
interactive_timeout = 600

# ================================================================
# QUERY CACHE (Disabled in MySQL 8.0+ by default)
# ================================================================
# Query cache removed in MySQL 8.0
# Use application-level caching (Redis) instead

# ================================================================
# TABLE CACHE
# ================================================================
table_open_cache = 4000
table_definition_cache = 2000
table_open_cache_instances = 16

# ================================================================
# SORT AND JOIN BUFFERS
# ================================================================
sort_buffer_size = 4M
join_buffer_size = 4M
read_buffer_size = 2M
read_rnd_buffer_size = 2M

# ================================================================
# TMP TABLE SETTINGS
# ================================================================
tmp_table_size = 256M
max_heap_table_size = 256M

# ================================================================
# BINARY LOGGING (For replication/recovery)
# ================================================================
log_bin = mysql-bin
binlog_format = ROW
binlog_row_image = MINIMAL
expire_logs_days = 7
sync_binlog = 0  # Async for performance (use 1 for safety)

# ================================================================
# PERFORMANCE SCHEMA
# ================================================================
performance_schema = ON
performance_schema_max_table_instances = 1000

# ================================================================
# PARTITIONING
# ================================================================
# Enable partitioning support
-- partitioning = ON  # Default in MySQL 8.0

# ================================================================
# CHARACTER SET
# ================================================================
character_set_server = utf8mb4
collation_server = utf8mb4_unicode_ci

# ================================================================
# ERROR LOGGING
# ================================================================
log_error = /var/log/mysql/error.log
log_error_verbosity = 2
slow_query_log = ON
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 0.1  # Log queries > 100ms
log_queries_not_using_indexes = ON
*/

-- ====================================================================
-- SECTION 2: CONNECTION POOL CONFIGURATION (HikariCP)
-- ====================================================================
/*
Spring Boot application.properties configuration:

# ================================================================
# HIKARICP POOL SETTINGS (Optimized for high-throughput)
# ================================================================

# Pool size = (2 * cores) + effective_spindle_count
# For 8-core server with NVMe: 2*8 + 1 = 17, round to 20
spring.datasource.hikari.maximum-pool-size=30
spring.datasource.hikari.minimum-idle=10

# Connection acquisition timeout (fail fast)
spring.datasource.hikari.connection-timeout=5000

# Validation timeout
spring.datasource.hikari.validation-timeout=3000

# Idle timeout before connection is closed
spring.datasource.hikari.idle-timeout=300000

# Max connection lifetime (slightly less than MySQL wait_timeout)
spring.datasource.hikari.max-lifetime=580000

# Leak detection
spring.datasource.hikari.leak-detection-threshold=30000

# Pool name for monitoring
spring.datasource.hikari.pool-name=DeauthDetectionPool

# Prepared statement cache (reduce parsing overhead)
spring.datasource.hikari.data-source-properties.cachePrepStmts=true
spring.datasource.hikari.data-source-properties.prepStmtCacheSize=500
spring.datasource.hikari.data-source-properties.prepStmtCacheSqlLimit=2048
spring.datasource.hikari.data-source-properties.useServerPrepStmts=true

# Batch operations
spring.datasource.hikari.data-source-properties.rewriteBatchedStatements=true

# Performance
spring.datasource.hikari.data-source-properties.cacheResultSetMetadata=true
spring.datasource.hikari.data-source-properties.cacheServerConfiguration=true
spring.datasource.hikari.data-source-properties.elideSetAutoCommits=true
spring.datasource.hikari.data-source-properties.maintainTimeStats=false
spring.datasource.hikari.data-source-properties.useLocalSessionState=true
spring.datasource.hikari.data-source-properties.useLocalTransactionState=true

# Timezone handling
spring.datasource.hikari.data-source-properties.serverTimezone=UTC
spring.datasource.hikari.data-source-properties.useLegacyDatetimeCode=false

# SSL for Aiven Cloud
spring.datasource.hikari.data-source-properties.useSSL=true
spring.datasource.hikari.data-source-properties.requireSSL=true
*/

-- ====================================================================
-- SECTION 3: CACHING LAYER RECOMMENDATIONS
-- ====================================================================
/*
Implement a multi-tier caching strategy:

┌─────────────────────────────────────────────────────────────────────┐
│                     CACHING ARCHITECTURE                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────┐                                           │
│  │   L1 Cache (JVM)    │  TTL: 1-5 seconds                         │
│  │   Caffeine/Guava    │  Size: 10,000 entries                     │
│  │                     │  Use for: Threshold lookups, rules        │
│  └──────────┬──────────┘                                           │
│             │ Miss                                                  │
│             ▼                                                       │
│  ┌─────────────────────┐                                           │
│  │   L2 Cache (Redis)  │  TTL: 1-5 minutes                         │
│  │   Cluster Mode      │  Size: Based on RAM                       │
│  │                     │  Use for: Baselines, aggregates           │
│  └──────────┬──────────┘                                           │
│             │ Miss                                                  │
│             ▼                                                       │
│  ┌─────────────────────┐                                           │
│  │   MySQL Database    │  Source of truth                          │
│  │   (with query cache │                                           │
│  │    at app level)    │                                           │
│  └─────────────────────┘                                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

CACHE KEY STRATEGIES:
=====================

1. Detection Thresholds (L1 Cache, 30s TTL)
   Key Pattern: "threshold:{entity_type}:{entity_id}"
   Example: "threshold:BSSID:00:11:22:33:44:55"
   Invalidation: On threshold update via @CacheEvict

2. Baseline Statistics (L2 Cache, 5min TTL)
   Key Pattern: "baseline:{type}:{id}:{window}"
   Example: "baseline:mac:AA:BB:CC:DD:EE:FF:HOUR"
   Invalidation: After baseline update job

3. Detection Rules (L1 Cache, 60s TTL)
   Key Pattern: "rules:{layer}:{enabled}"
   Example: "rules:LAYER_1:true"
   Invalidation: On rule modification

4. Rate Aggregates (L2 Cache, 1min TTL)
   Key Pattern: "rate:{granularity}:{scope}:{id}:{bucket}"
   Example: "rate:5MIN:GLOBAL:null:2026020708"
   Invalidation: After aggregation job

REDIS CONFIGURATION:
====================
redis:
  cluster:
    nodes:
      - redis-1:6379
      - redis-2:6379
      - redis-3:6379
  timeout: 1000ms
  lettuce:
    pool:
      max-active: 50
      max-idle: 20
      min-idle: 5
      max-wait: 1000ms

SPRING CACHE CONFIGURATION:
===========================
@Configuration
@EnableCaching
public class CacheConfig {
    
    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager manager = new CaffeineCacheManager();
        manager.setCaffeine(Caffeine.newBuilder()
            .maximumSize(10_000)
            .expireAfterWrite(30, TimeUnit.SECONDS)
            .recordStats());
        return manager;
    }
    
    @Bean
    public RedisCacheManager redisCacheManager(RedisConnectionFactory factory) {
        RedisCacheConfiguration config = RedisCacheConfiguration.defaultCacheConfig()
            .entryTtl(Duration.ofMinutes(5))
            .serializeValuesWith(
                SerializationPair.fromSerializer(new GenericJackson2JsonRedisSerializer()));
        
        return RedisCacheManager.builder(factory)
            .cacheDefaults(config)
            .withCacheConfiguration("baselines", 
                config.entryTtl(Duration.ofMinutes(5)))
            .withCacheConfiguration("thresholds", 
                config.entryTtl(Duration.ofSeconds(30)))
            .withCacheConfiguration("rates", 
                config.entryTtl(Duration.ofMinutes(1)))
            .build();
    }
}
*/

-- ====================================================================
-- SECTION 4: QUERY OPTIMIZATION SETTINGS
-- ====================================================================

-- ================================================================
-- Session-level optimizer settings for detection queries
-- ================================================================

-- Enable batched key access for joins
SET SESSION optimizer_switch = 'batched_key_access=on';

-- Enable index condition pushdown
SET SESSION optimizer_switch = 'index_condition_pushdown=on';

-- Enable MRR (Multi-Range Read)
SET SESSION optimizer_switch = 'mrr=on,mrr_cost_based=off';

-- Enable hash joins (MySQL 8.0.18+)
SET SESSION optimizer_switch = 'hash_join=on';

-- Skip locked rows for high-concurrency reads
-- Use: SELECT ... FOR UPDATE SKIP LOCKED

-- ================================================================
-- Partitioned table optimizations
-- ================================================================

-- Force partition pruning in queries
SET SESSION optimizer_switch = 'subquery_materialization_cost_based=off';

-- ====================================================================
-- SECTION 5: BATCH INSERT OPTIMIZATION
-- ====================================================================
/*
For high-volume frame inserts (1000-5000/sec):

1. Use batch inserts instead of single inserts:
   INSERT INTO frame_tracking (...) VALUES (...), (...), (...), ...
   Batch size: 100-500 rows per statement

2. Use INSERT DELAYED or LOAD DATA INFILE for bulk loads

3. Disable foreign key checks during bulk inserts:
   SET FOREIGN_KEY_CHECKS = 0;
   -- bulk insert
   SET FOREIGN_KEY_CHECKS = 1;

4. Use transactions for batch commits:
   START TRANSACTION;
   -- insert batch
   COMMIT;
   
   Commit every 1000-5000 rows

5. Consider using MySQL Shell's parallel import for initial loads

JAVA BATCH INSERT EXAMPLE:
=========================
@Repository
public class FrameTrackingBatchRepository {
    
    private static final int BATCH_SIZE = 500;
    
    @PersistenceContext
    private EntityManager entityManager;
    
    @Transactional
    public void batchInsert(List<FrameTracking> frames) {
        for (int i = 0; i < frames.size(); i++) {
            entityManager.persist(frames.get(i));
            
            if (i > 0 && i % BATCH_SIZE == 0) {
                entityManager.flush();
                entityManager.clear();
            }
        }
        entityManager.flush();
        entityManager.clear();
    }
}

JPA BATCH SETTINGS:
==================
spring.jpa.properties.hibernate.jdbc.batch_size=500
spring.jpa.properties.hibernate.order_inserts=true
spring.jpa.properties.hibernate.order_updates=true
spring.jpa.properties.hibernate.batch_versioned_data=true
*/

-- ====================================================================
-- SECTION 6: MONITORING QUERIES
-- ====================================================================

-- ================================================================
-- Query: Buffer Pool Status
-- ================================================================
SELECT 
    FORMAT(@@innodb_buffer_pool_size / 1024 / 1024 / 1024, 2) as buffer_pool_gb,
    FORMAT(
        (SELECT VARIABLE_VALUE FROM performance_schema.global_status 
         WHERE VARIABLE_NAME = 'Innodb_buffer_pool_reads') /
        NULLIF(
            (SELECT VARIABLE_VALUE FROM performance_schema.global_status 
             WHERE VARIABLE_NAME = 'Innodb_buffer_pool_read_requests'),
            0
        ) * 100, 4
    ) as buffer_miss_rate_pct;

-- ================================================================
-- Query: Connection Pool Status
-- ================================================================
SELECT 
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status 
     WHERE VARIABLE_NAME = 'Threads_connected') as current_connections,
    @@max_connections as max_connections,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status 
     WHERE VARIABLE_NAME = 'Threads_running') as active_threads,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status 
     WHERE VARIABLE_NAME = 'Connection_errors_max_connections') as connection_errors;

-- ================================================================
-- Query: Query Performance Summary
-- ================================================================
SELECT 
    DIGEST_TEXT,
    COUNT_STAR as executions,
    ROUND(AVG_TIMER_WAIT / 1000000000, 3) as avg_time_ms,
    ROUND(MAX_TIMER_WAIT / 1000000000, 3) as max_time_ms,
    SUM_ROWS_EXAMINED as rows_examined,
    SUM_ROWS_SENT as rows_sent
FROM performance_schema.events_statements_summary_by_digest
WHERE SCHEMA_NAME = DATABASE()
ORDER BY AVG_TIMER_WAIT DESC
LIMIT 20;

-- ================================================================
-- Query: Index Usage Statistics
-- ================================================================
SELECT 
    OBJECT_SCHEMA,
    OBJECT_NAME as table_name,
    INDEX_NAME,
    COUNT_STAR as total_accesses,
    COUNT_READ as reads,
    COUNT_WRITE as writes,
    COUNT_FETCH as fetches
FROM performance_schema.table_io_waits_summary_by_index_usage
WHERE OBJECT_SCHEMA = DATABASE()
  AND INDEX_NAME IS NOT NULL
ORDER BY COUNT_STAR DESC
LIMIT 30;

-- ================================================================
-- Query: Lock Wait Analysis
-- ================================================================
SELECT 
    r.trx_id AS waiting_trx_id,
    r.trx_mysql_thread_id AS waiting_thread,
    r.trx_query AS waiting_query,
    b.trx_id AS blocking_trx_id,
    b.trx_mysql_thread_id AS blocking_thread,
    b.trx_query AS blocking_query
FROM information_schema.innodb_lock_waits w
JOIN information_schema.innodb_trx b ON b.trx_id = w.blocking_trx_id
JOIN information_schema.innodb_trx r ON r.trx_id = w.requesting_trx_id;

-- ====================================================================
-- SECTION 7: ALERTING THRESHOLDS
-- ====================================================================
/*
Set up monitoring alerts for these conditions:

CRITICAL ALERTS:
- Buffer pool hit rate < 99%
- Connection pool utilization > 90%
- Average query time > 10ms for detection queries
- Lock waits > 100/minute
- Replication lag > 5 seconds

WARNING ALERTS:
- Buffer pool hit rate < 99.5%
- Connection pool utilization > 75%
- Average query time > 5ms
- Slow queries > 10/minute
- Disk I/O wait > 10ms

RECOMMENDED MONITORING TOOLS:
- MySQL Enterprise Monitor
- Percona Monitoring and Management (PMM)
- Prometheus + MySQL Exporter + Grafana
- Datadog MySQL Integration
*/
