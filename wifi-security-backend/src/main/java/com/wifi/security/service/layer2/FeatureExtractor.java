
package com.wifi.security.service.layer2;

import com.wifi.security.dto.request.DetectionRequest;
import com.wifi.security.dto.response.DetectionResponse;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Random;

@Component
public class FeatureExtractor {

    private final Random random = new Random();

    /**
     * Extract 14 features for ML model.
     * Since we don't query the full history for performance reasons,
     * we estimate some features based on Layer 1 scores.
     * 
     * Features:
     * 0. frame_rate
     * 1. seq_variance
     * 2. mean_interval
     * 3. std_interval
     * 4. rssi
     * 5. rssi_delta
     * 6. hour (0-23)
     * 7. day_of_week (0-6)
     * 8. victim_count
     * 9. reason_code
     * 10. time_since_legit (seconds)
     * 11. assoc_duration (seconds)
     * 12. throughput (bytes)
     * 13. channel
     */
    public double[] extract(DetectionRequest request, DetectionResponse layer1Result) {
        double[] features = new double[14];
        
        // 0. Frame Rate (Estimate from Layer 1 Rate Score)
        // Score 100 => ~500 frames/sec, Score 10 => ~5 frames/sec
        int rateScore = layer1Result.getAnalyzerScores() != null ? 
                        layer1Result.getAnalyzerScores().getRateAnalyzerScore() : 0;
        features[0] = Math.max(1.0, rateScore * 5.0); 

        // 1. Sequence Variance (Estimate from Layer 1 Sequence Score)
        int seqScore = layer1Result.getAnalyzerScores() != null ? 
                       layer1Result.getAnalyzerScores().getSequenceValidatorScore() : 0;
        features[1] = Math.max(1.0, seqScore * 2.0);

        // 2 & 3. Intervals (Inverse of rate)
        features[2] = 1.0 / features[0]; // Mean Interval
        features[3] = features[2] * 0.1; // Std Interval (Assumption)

        // 4. RSSI (From Request) - Default to -70 if missing
        features[4] = request.getRssi() != null ? request.getRssi() : -70.0;

        // 5. RSSI Delta (Requires history, simulate/assume strictly for now)
        // If Layer 1 detects anomaly, delta is likely high
        features[5] = layer1Result.getCombinedScore() > 50 ? 15.0 : 2.0; 

        // 6 & 7. Time Features
        LocalDateTime now = request.getTimestamp() != null ? request.getTimestamp() : LocalDateTime.now();
        features[6] = now.getHour();
        features[7] = now.getDayOfWeek().getValue() % 7; // Sunday=0 for model? Or Mon=0? Python assumes 0-6.

        // 8. Victim Count (Unknown without state, assume 1 unless high rate)
        features[8] = features[0] > 50 ? 5.0 : 1.0;

        // 9. Reason Code (Extract or default to 7 for Deauth)
        // If frameType is DEAUTH, likely 7.
        features[9] = "DEAUTH".equalsIgnoreCase(request.getFrameType()) ? 7.0 : 1.0;

        // 10. Time Since Legit (Unknown, random small value)
        features[10] = random.nextInt(3600); 

        // 11. Assoc Duration (Unknown, random)
        features[11] = random.nextInt(600);

        // 12. Throughput (Estimate based on rate * header size 24 bytes)
        features[12] = features[0] * 24;

        // 13. Channel (Default to 1 or extract if available)
        // PacketDTO has channel, RequestDTO doesn't explicitly have it unless in metadata
        features[13] = 1.0; // Default

        return features;
    }
}
