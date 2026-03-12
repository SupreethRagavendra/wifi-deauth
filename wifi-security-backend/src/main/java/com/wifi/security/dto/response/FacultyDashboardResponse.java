package com.wifi.security.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class FacultyDashboardResponse {
    private String networkStatus;
    private int connectedClientsCount;
    private String apSignalStrength;
    private String securityMode;
    private String speed;
    private String threatLevel;
    private String activeBssid;
    private String activeSsid;

    @JsonProperty("isDeviceConnected")
    private boolean isDeviceConnected;
}
