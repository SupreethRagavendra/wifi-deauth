
package com.wifi.security.service.layer2;

import com.wifi.security.dto.request.DetectionRequest;
import com.wifi.security.dto.response.DetectionResponse;
import com.wifi.security.dto.response.AnalyzerScore;
import com.wifi.security.service.layer2.FeatureExtractor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class Layer2Service {
    
    private static final Logger logger = LoggerFactory.getLogger(Layer2Service.class);
    
    @Value("${ml.api.url:http://localhost:5000}")
    private String mlApiUrl;
    
    private final RestTemplate restTemplate;
    private final FeatureExtractor featureExtractor;
    
    public Layer2Service(FeatureExtractor featureExtractor) {
        this.restTemplate = new RestTemplate();
        this.featureExtractor = featureExtractor;
    }
    
    /**
     * Analyze using ML ensemble
     */
    public DetectionResponse analyzeWithML(DetectionRequest request, DetectionResponse layer1Result) {
        try {
            logger.debug("Starting Layer 2 ML analysis for {}", request.getSourceMac());
            
            // Extract 14 features
            double[] features = featureExtractor.extract(request, layer1Result);
            
            // Call ML API
            MLPrediction prediction = callMLAPI(features);
            
            if (prediction == null) {
                // Should have been caught by exception, but just in case
                return layer1Result;
            }

            // Update response with ML data
            layer1Result.setDtVote(prediction.getDetails().getOrDefault("decision_tree", 0.0).intValue());
            layer1Result.setRfVote(prediction.getDetails().getOrDefault("random_forest", 0.0).intValue());
            
            // Extract details from the "details" map in prediction if present
            Map<String, Double> details = prediction.getDetails();
            if (details != null) {
                 // The API returns percentage confidence (0-100), we can store as integer votes closer to 0 or 1
                 // Or just store the raw confidence as "vote" confidence?
                 // The DTO has Integer for votes. The API returns floats.
                 // Let's store the CONFIDENCE in the DTO as mlConfidence
            }

            layer1Result.setMlConfidence(prediction.getConfidence());
            layer1Result.setLayer2Score((int) prediction.getConfidence());
            
            logger.info("Layer 2 ML Result: Confidence={}%, Verdict={}", 
                prediction.getConfidence(), prediction.getVerdict());
            
            return layer1Result;
            
        } catch (Exception e) {
            logger.error("Layer 2 ML analysis failed: {}", e.getMessage());
            // Fallback: skip ML, use only Layer 1
            layer1Result.setMlConfidence(0.0);
            layer1Result.setLayer2Score(0);
            return layer1Result;
        }
    }
    
    /**
     * Call Python ML API
     */
    private MLPrediction callMLAPI(double[] features) {
        try {
            // Prepare request
            Map<String, Object> requestBody = new HashMap<>();
            requestBody.put("features", features);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
            
            // Call API
            String url = mlApiUrl + "/predict";
            ResponseEntity<MLPrediction> response = restTemplate.postForEntity(
                url, entity, MLPrediction.class
            );
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                return response.getBody();
            } else {
                throw new RuntimeException("ML API returned non-OK status: " + response.getStatusCode());
            }
            
        } catch (Exception e) {
            logger.error("Failed to call ML API at {}: {}", mlApiUrl, e.getMessage());
            throw e;
        }
    }
    
    /**
     * ML Prediction DTO (Matches Python API Response)
     */
    public static class MLPrediction {
        private String verdict;
        private double confidence;
        private Map<String, Double> details;
        
        public String getVerdict() { return verdict; }
        public void setVerdict(String verdict) { this.verdict = verdict; }
        
        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }
        
        public Map<String, Double> getDetails() { return details; }
        public void setDetails(Map<String, Double> details) { this.details = details; }
    }
}
