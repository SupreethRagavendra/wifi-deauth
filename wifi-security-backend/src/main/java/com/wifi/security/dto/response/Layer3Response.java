package com.wifi.security.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Layer3Response {
    private int physicalScore; // 0-70
    private int rssiScore;
    private int multiClientScore;
    private int broadcastScore;
    private String analysisNotes;
}
