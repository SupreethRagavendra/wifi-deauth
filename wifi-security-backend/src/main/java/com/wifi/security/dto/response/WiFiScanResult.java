package com.wifi.security.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class WiFiScanResult {
    private String ssid;
    private String bssid;
    private int rssi;
    private String security;
    private int channel;
    // Map snake_case from python to camelCase here if needed, or update python.
    // Python outputs "estimated_distance". Jackson usually needs matching name or
    // annotation.
    @com.fasterxml.jackson.annotation.JsonProperty("estimated_distance")
    private String estimatedDistance;
}
