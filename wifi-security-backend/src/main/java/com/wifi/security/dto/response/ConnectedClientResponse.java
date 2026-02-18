package com.wifi.security.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ConnectedClientResponse {
    private String macAddress;
    private String hostname;
    private String ipAddress;
    private String signalStrength;
    private String connectionTime;
}
