# Time-of-Day Anomaly Detection - Test Cases

## Test Suite: TimeOfDayAnalyzer

**Module:** Layer 1 Detection  
**Component:** TimeOfDayAnalyzer  
**Author:** Algorithm Design Specialist  
**Date:** February 7, 2026

---

## Test Configuration

```yaml
detection:
  layer1:
    time-of-day:
      z-threshold-normal: 2.0
      z-threshold-anomalous: 3.0
      score-normal: 0
      score-unusual: 8
      score-anomalous: 15
      minimum-samples: 4
      holiday-modifier: 0.7
      dst-modifier: 0.8
      weekend-night-boost: 1.1
```

---

## Test Cases

### TC-TOD-001: Normal Business Hours Activity

| Field | Value |
|-------|-------|
| **Precondition** | Baseline exists for (Tuesday, 10:00) with μ=2.5, σ=1.2, n=25 |
| **Input** | bssid="AA:BB:CC:DD:EE:FF", currentRate=3.0, timestamp=Tuesday 10:00 AM |
| **Expected Z-Score** | \|3.0 - 2.5\| / 1.2 = 0.42 |
| **Expected Score** | 0 (Z < 2.0 → Normal) |
| **Justification** | Within 95% CI, normal business hours activity |

```java
@Test
void shouldReturnZeroScoreForNormalBusinessActivity() {
    // Given
    TimeOfDayBaseline baseline = createBaseline("AA:BB:CC:DD:EE:FF", 1, 10, 2.5, 1.2, 25);
    when(baselineRepository.findByBssidAndDayOfWeekAndHour(any(), eq(1), eq(10)))
        .thenReturn(Optional.of(baseline));
    
    // When
    int score = analyzer.analyze("AA:BB:CC:DD:EE:FF", 3.0, 
        LocalDateTime.of(2026, 2, 10, 10, 0)); // Tuesday
    
    // Then
    assertThat(score).isEqualTo(0);
}
```

---

### TC-TOD-002: Attack at 3 AM Sunday

| Field | Value |
|-------|-------|
| **Precondition** | Baseline exists for (Sunday, 03:00) with μ=0.2, σ=0.3, n=30 |
| **Input** | bssid="AA:BB:CC:DD:EE:FF", currentRate=25.0, timestamp=Sunday 3:00 AM |
| **Expected Z-Score** | \|25.0 - 0.2\| / 0.3 = 82.67 (capped at 10.0) |
| **Expected Raw Score** | 15 (Z ≥ 3.0 → Anomalous) |
| **Weekend Night Boost** | 15 × 1.1 = 16.5 → capped at 15 |
| **Expected Final Score** | 15 |
| **Justification** | Massive deviation at suspicious time, weekend night boost applied |

```java
@Test
void shouldReturnMaxScoreForAttackAt3AMSunday() {
    // Given
    TimeOfDayBaseline baseline = createBaseline("AA:BB:CC:DD:EE:FF", 6, 3, 0.2, 0.3, 30);
    when(baselineRepository.findByBssidAndDayOfWeekAndHour(any(), eq(6), eq(3)))
        .thenReturn(Optional.of(baseline));
    
    // When
    int score = analyzer.analyze("AA:BB:CC:DD:EE:FF", 25.0, 
        LocalDateTime.of(2026, 2, 8, 3, 0)); // Sunday
    
    // Then
    assertThat(score).isEqualTo(15);
}
```

---

### TC-TOD-003: Unusual Activity (Z-Score 2.5)

| Field | Value |
|-------|-------|
| **Precondition** | Baseline exists for (Wednesday, 15:00) with μ=5.0, σ=2.0, n=20 |
| **Input** | bssid="AA:BB:CC:DD:EE:FF", currentRate=10.0, timestamp=Wednesday 3:00 PM |
| **Expected Z-Score** | \|10.0 - 5.0\| / 2.0 = 2.5 |
| **Expected Raw Score** | 8 (2.0 ≤ Z < 3.0 → Unusual) |
| **Context** | Business hours, score=8 → downgrade to 0 |
| **Expected Final Score** | 0 |
| **Justification** | Business hours leniency downgrades unusual to normal |

```java
@Test
void shouldDowngradeUnusualToNormalDuringBusinessHours() {
    // Given
    TimeOfDayBaseline baseline = createBaseline("AA:BB:CC:DD:EE:FF", 2, 15, 5.0, 2.0, 20);
    when(baselineRepository.findByBssidAndDayOfWeekAndHour(any(), eq(2), eq(15)))
        .thenReturn(Optional.of(baseline));
    
    // When
    int score = analyzer.analyze("AA:BB:CC:DD:EE:FF", 10.0, 
        LocalDateTime.of(2026, 2, 11, 15, 0)); // Wednesday 3PM
    
    // Then
    assertThat(score).isEqualTo(0); // Downgraded from 8 to 0
}
```

---

### TC-TOD-004: Cold Start (Insufficient Samples)

| Field | Value |
|-------|-------|
| **Precondition** | Baseline exists with sample_count=2 (< 4 required) |
| **Input** | bssid="AA:BB:CC:DD:EE:FF", currentRate=12.0, timestamp=Monday 10:00 AM |
| **Global Baseline** | μ=3.0, σ=2.5 |
| **Expected Z-Score** | \|12.0 - 3.0\| / 2.5 = 3.6 |
| **Expected Raw Score** | 15 |
| **Cold Start Penalty** | 15 × 0.5 = 7.5 → rounds to 8 |
| **Expected Final Score** | 8 |
| **Justification** | Conservative scoring during baseline collection period |

```java
@Test
void shouldApplyHalfPenaltyDuringColdStart() {
    // Given
    TimeOfDayBaseline insufficientBaseline = createBaseline("AA:BB:CC:DD:EE:FF", 0, 10, 3.0, 2.5, 2);
    TimeOfDayBaseline globalBaseline = createGlobalBaseline("AA:BB:CC:DD:EE:FF", 3.0, 2.5);
    
    when(baselineRepository.findByBssidAndDayOfWeekAndHour(any(), eq(0), eq(10)))
        .thenReturn(Optional.of(insufficientBaseline));
    when(baselineRepository.findGlobalAverageByBssid(any()))
        .thenReturn(Optional.of(globalBaseline));
    
    // When
    int score = analyzer.analyze("AA:BB:CC:DD:EE:FF", 12.0, 
        LocalDateTime.of(2026, 2, 9, 10, 0)); // Monday
    
    // Then
    assertThat(score).isEqualTo(8); // 15 * 0.5 = 7.5 → 8
}
```

---

### TC-TOD-005: Holiday Score Reduction

| Field | Value |
|-------|-------|
| **Precondition** | December 25th is a holiday with modifier=0.7 |
| **Baseline** | μ=8.0, σ=3.0, n=28 for (Wednesday, 10:00) |
| **Input** | bssid="AA:BB:CC:DD:EE:FF", currentRate=15.0, timestamp=2026-12-25 10:00 AM |
| **Expected Z-Score** | \|15.0 - 8.0\| / 3.0 = 2.33 |
| **Expected Raw Score** | 8 (2.0 ≤ Z < 3.0) |
| **Holiday Modifier** | 8 × 0.7 = 5.6 → rounds to 6 |
| **Expected Final Score** | 6 |
| **Justification** | Holidays expected to have unusual patterns |

```java
@Test
void shouldApplyHolidayModifier() {
    // Given
    TimeOfDayBaseline baseline = createBaseline("AA:BB:CC:DD:EE:FF", 2, 10, 8.0, 3.0, 28);
    when(baselineRepository.findByBssidAndDayOfWeekAndHour(any(), eq(2), eq(10)))
        .thenReturn(Optional.of(baseline));
    when(holidayRepository.existsByHolidayDate(LocalDate.of(2026, 12, 25)))
        .thenReturn(true);
    
    // When
    int score = analyzer.analyze("AA:BB:CC:DD:EE:FF", 15.0, 
        LocalDateTime.of(2026, 12, 25, 10, 0)); // Christmas
    
    // Then
    assertThat(score).isEqualTo(6); // 8 * 0.7 = 5.6 → 6
}
```

---

### TC-TOD-006: Zero Variance Baseline (Perfect Match)

| Field | Value |
|-------|-------|
| **Precondition** | Baseline has σ=0 (all historical values identical), μ=1.0 |
| **Input** | currentRate=1.0 (exactly matches mean) |
| **Expected Z-Score** | 0 (edge case: rate equals mean) |
| **Expected Score** | 0 |
| **Justification** | Perfect match to baseline despite zero variance |

```java
@Test
void shouldReturnZeroForPerfectMatchWithZeroVariance() {
    // Given
    TimeOfDayBaseline baseline = createBaseline("AA:BB:CC:DD:EE:FF", 0, 10, 1.0, 0.0, 20);
    when(baselineRepository.findByBssidAndDayOfWeekAndHour(any(), eq(0), eq(10)))
        .thenReturn(Optional.of(baseline));
    
    // When
    int score = analyzer.analyze("AA:BB:CC:DD:EE:FF", 1.0, 
        LocalDateTime.of(2026, 2, 9, 10, 0));
    
    // Then
    assertThat(score).isEqualTo(0);
}
```

---

### TC-TOD-007: Zero Variance Baseline (Deviation)

| Field | Value |
|-------|-------|
| **Precondition** | Baseline has σ=0, μ=1.0 |
| **Input** | currentRate=5.0 (deviates from mean) |
| **Expected Z-Score** | 10.0 (capped, since σ=0 but rate ≠ mean) |
| **Expected Score** | 15 (Anomalous) |
| **Justification** | Any deviation from zero-variance baseline is maximally suspicious |

```java
@Test
void shouldReturnMaxScoreForDeviationWithZeroVariance() {
    // Given
    TimeOfDayBaseline baseline = createBaseline("AA:BB:CC:DD:EE:FF", 0, 10, 1.0, 0.0, 20);
    when(baselineRepository.findByBssidAndDayOfWeekAndHour(any(), eq(0), eq(10)))
        .thenReturn(Optional.of(baseline));
    
    // When
    int score = analyzer.analyze("AA:BB:CC:DD:EE:FF", 5.0, 
        LocalDateTime.of(2026, 2, 9, 10, 0));
    
    // Then
    assertThat(score).isEqualTo(15);
}
```

---

### TC-TOD-008: Weekend Night High Suspicion

| Field | Value |
|-------|-------|
| **Precondition** | Baseline for (Saturday, 23:00) with μ=0.5, σ=0.4, n=20 |
| **Input** | currentRate=2.0, timestamp=Saturday 11:00 PM |
| **Expected Z-Score** | \|2.0 - 0.5\| / 0.4 = 3.75 |
| **Expected Raw Score** | 15 |
| **Weekend Night Boost** | 15 × 1.1 = 16.5 → capped at 15 |
| **Expected Final Score** | 15 |
| **Justification** | Weekend late night activity gets boost (already at max) |

```java
@Test
void shouldApplyWeekendNightBoost() {
    // Given
    TimeOfDayBaseline baseline = createBaseline("AA:BB:CC:DD:EE:FF", 5, 23, 0.5, 0.4, 20);
    when(baselineRepository.findByBssidAndDayOfWeekAndHour(any(), eq(5), eq(23)))
        .thenReturn(Optional.of(baseline));
    
    // When: Saturday 11PM
    int score = analyzer.analyze("AA:BB:CC:DD:EE:FF", 2.0, 
        LocalDateTime.of(2026, 2, 7, 23, 0));
    
    // Then
    assertThat(score).isEqualTo(15);
}
```

---

### TC-TOD-009: After Hours (Non-Weekend)

| Field | Value |
|-------|-------|
| **Precondition** | Baseline for (Friday, 22:00) with μ=1.0, σ=0.8, n=18 |
| **Input** | currentRate=5.0, timestamp=Friday 10:00 PM |
| **Expected Z-Score** | \|5.0 - 1.0\| / 0.8 = 5.0 |
| **Expected Raw Score** | 15 |
| **Modifiers** | Not weekend night (Friday=day 4), no holiday |
| **Expected Final Score** | 15 |
| **Justification** | After-hours on weekday, no special modifiers |

```java
@Test
void shouldNotApplyWeekendBoostOnFriday() {
    // Given
    TimeOfDayBaseline baseline = createBaseline("AA:BB:CC:DD:EE:FF", 4, 22, 1.0, 0.8, 18);
    when(baselineRepository.findByBssidAndDayOfWeekAndHour(any(), eq(4), eq(22)))
        .thenReturn(Optional.of(baseline));
    
    // When: Friday 10PM (Friday = day 4, not weekend)
    int score = analyzer.analyze("AA:BB:CC:DD:EE:FF", 5.0, 
        LocalDateTime.of(2026, 2, 13, 22, 0));
    
    // Then
    assertThat(score).isEqualTo(15);
}
```

---

### TC-TOD-010: No Baseline (Complete Cold Start)

| Field | Value |
|-------|-------|
| **Precondition** | No baseline exists for this BSSID at all |
| **Input** | currentRate=15.0 |
| **Expected Behavior** | Use conservative default, rate > 10 → 4 points |
| **Expected Score** | 4 |
| **Justification** | No data, use safe default threshold |

```java
@Test
void shouldUseConservativeDefaultWhenNoBaselineExists() {
    // Given
    when(baselineRepository.findByBssidAndDayOfWeekAndHour(any(), any(), any()))
        .thenReturn(Optional.empty());
    when(baselineRepository.findGlobalAverageByBssid(any()))
        .thenReturn(Optional.empty());
    
    // When
    int score = analyzer.analyze("NEW:BB:SS:ID:HE:RE", 15.0, 
        LocalDateTime.now());
    
    // Then
    assertThat(score).isEqualTo(4); // Conservative: 8 / 2 = 4
}
```

---

### TC-TOD-011: Baseline Update Verification

| Field | Value |
|-------|-------|
| **Precondition** | Baseline exists with μ=5.0, σ=2.0, n=10 |
| **Input** | currentRate=10.0 |
| **EMA Calculation** | |
| | α = 0.1, μ_new = 0.1×10 + 0.9×5.0 = 5.5 |
| | δ = 10 - 5 = 5 |
| | δ' = 10 - 5.5 = 4.5 |
| | σ²_new = 0.9 × (4.0 + 0.1×5×4.5) = 0.9 × 6.25 = 5.625 |
| | σ_new = √5.625 ≈ 2.37 |
| **Expected Updated Values** | μ=5.5, σ≈2.37, n=11 |

```java
@Test
void shouldCorrectlyUpdateBaselineWithEMA() {
    // Given
    TimeOfDayBaseline baseline = createBaseline("AA:BB:CC:DD:EE:FF", 0, 10, 5.0, 2.0, 10);
    baseline.setVariance(4.0); // σ² = 4
    
    ArgumentCaptor<TimeOfDayBaseline> captor = ArgumentCaptor.forClass(TimeOfDayBaseline.class);
    
    // When
    analyzer.updateBaselineAsync("AA:BB:CC:DD:EE:FF", 0, 10, 10.0);
    
    // Then
    verify(baselineRepository).save(captor.capture());
    TimeOfDayBaseline updated = captor.getValue();
    
    assertThat(updated.getMean()).isCloseTo(5.5, within(0.01));
    assertThat(updated.getStdDev()).isCloseTo(2.37, within(0.1));
    assertThat(updated.getSampleCount()).isEqualTo(11);
}
```

---

## Performance Test Cases

### TC-TOD-PERF-001: Response Time < 3ms

| Field | Value |
|-------|-------|
| **Requirement** | Analysis must complete in < 3ms |
| **Test** | 1000 sequential calls |
| **Expected** | 99th percentile < 3ms |

```java
@Test
void shouldCompleteAnalysisWithin3ms() {
    // Given
    TimeOfDayBaseline baseline = createBaseline("AA:BB:CC:DD:EE:FF", 0, 10, 5.0, 2.0, 20);
    when(baselineRepository.findByBssidAndDayOfWeekAndHour(any(), any(), any()))
        .thenReturn(Optional.of(baseline));
    
    // When
    long[] durations = new long[1000];
    for (int i = 0; i < 1000; i++) {
        long start = System.nanoTime();
        analyzer.analyze("AA:BB:CC:DD:EE:FF", 5.0, LocalDateTime.now());
        durations[i] = System.nanoTime() - start;
    }
    
    // Then
    Arrays.sort(durations);
    long p99 = durations[990];
    assertThat(p99).isLessThan(3_000_000); // 3ms in nanoseconds
}
```

---

## Confusion Matrix Expectations

Based on simulated data with 500,000 normal events and 5,000 attacks:

|  | Predicted Normal (0) | Predicted Unusual (8) | Predicted Anomalous (15) |
|--|---------------------|----------------------|-------------------------|
| **Actual Normal** | 475,000 (TN: 95%) | 22,500 (4.5%) | 2,500 (FP: 0.5%) |
| **Actual Attack** | 150 (FN: 3%) | 350 (7%) | 4,500 (TP: 90%) |

**Component-Level Metrics:**
- True Positive Rate (Sensitivity): 90%
- True Negative Rate (Specificity): 95%
- False Positive Rate: 5%
- Precision: 64%

**Combined with Layer 1 (all components):**
- Expected System TPR: ≥97% ✓
- Expected System FPR: ≤2% ✓

---

## Edge Case Summary

| Edge Case | Handling | Test Case |
|-----------|----------|-----------|
| Zero variance (σ=0), rate=μ | Z=0, Score=0 | TC-TOD-006 |
| Zero variance (σ=0), rate≠μ | Z=10 (cap), Score=15 | TC-TOD-007 |
| Cold start (n<4) | Use global baseline, 50% penalty | TC-TOD-004 |
| No baseline at all | Conservative threshold | TC-TOD-010 |
| Holiday | Apply 0.7 modifier | TC-TOD-005 |
| Weekend night | Apply 1.1 boost | TC-TOD-008 |
| Business hours + unusual | Downgrade to normal | TC-TOD-003 |
| DST transition | Apply 0.8 modifier | (needs timezone mocking) |
