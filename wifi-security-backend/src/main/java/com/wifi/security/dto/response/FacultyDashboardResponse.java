package com.wifi.security.dto.response;

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
    private boolean isDeviceConnected;
}
