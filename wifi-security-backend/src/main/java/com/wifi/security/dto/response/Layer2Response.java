package com.wifi.security.dto.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class Layer2Response {

    @JsonProperty("ml_score")
    private int mlScore;

    private String prediction;

    private double confidence;

    @JsonProperty("ensemble_agreement")
    private String modelAgreement;

    @JsonProperty("top_features")
    private List<String> topFeatures;
}
