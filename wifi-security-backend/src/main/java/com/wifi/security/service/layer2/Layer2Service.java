
package com.wifi.security.service.layer2;

import com.wifi.security.dto.request.DetectionRequest;
import com.wifi.security.dto.response.DetectionResponse;
import com.wifi.security.dto.response.Layer2Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class Layer2Service {

    private static final Logger logger = LoggerFactory.getLogger(Layer2Service.class);

    private final RestTemplate restTemplate;

    @Value("${ml.api.url:http://localhost:5000}")
    private String mlApiUrl;

    public Layer2Service() {
        // 500ms timeout max as requested
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(500);
        factory.setReadTimeout(500);
        this.restTemplate = new RestTemplate(factory);
    }

    public Layer2Response analyzeWithML(DetectionRequest request, DetectionResponse layer1Response) {
        try {
            // Re-structure request data for python ML logic
            Map<String, Object> payload = new HashMap<>();
            payload.put("src", request.getSourceMac());
            payload.put("dst", request.getBssid()); // Assuming dst is BSSID or broadcast
            payload.put("bssid", request.getBssid());
            payload.put("signal", request.getRssi());
            payload.put("channel", 1); // Mock mapping or retrieve from request
            payload.put("reason", 7); // Mock mapping or retrieve from request
            payload.put("seq", System.currentTimeMillis() % 10000); // Or retrieve exact sequence if available in
                                                                    // request

            // Add a proper timestamp (epoch in seconds)
            long epochSeconds = request.getTimestamp() != null
                    ? request.getTimestamp().atZone(java.time.ZoneId.systemDefault()).toEpochSecond()
                    : System.currentTimeMillis() / 1000;
            payload.put("timestamp", epochSeconds);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(payload, headers);

            logger.debug("Requesting Layer 2 ML analysis for packet from {}", request.getSourceMac());

            // POST to ML service
            String url = mlApiUrl + "/predict";
            Layer2Response mlResponse = restTemplate.postForObject(url, entity, Layer2Response.class);

            if (mlResponse != null) {
                logger.info("Layer 2 ML Result: Prediction={}, Confidence={}%, Score={}, Agreement={}",
                        mlResponse.getPrediction(), mlResponse.getConfidence() * 100, mlResponse.getMlScore(),
                        mlResponse.getModelAgreement());
                return mlResponse;
            }

        } catch (Exception e) {
            logger.warn("ML Service unreachable or timed out. Falling back to Layer 1. Error: {}", e.getMessage());
        }

        // Default Fallback
        return Layer2Response.builder()
                .mlScore(0)
                .prediction("UNKNOWN")
                .confidence(0.0)
                .modelAgreement("0/4")
                .build();
    }
}
