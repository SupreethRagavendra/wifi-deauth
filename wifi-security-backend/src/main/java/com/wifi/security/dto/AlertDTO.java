package com.wifi.security.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class AlertDTO {
    private String type; // DEAUTH_FLOOD, SEQ_ANOMALY, RSSI_ANOMALY
    private String severity; // HIGH, MEDIUM, LOW
    private String message;
    private String attackerMac;
    private String targetBssid;
    private int packetCount;
    private int timeWindow;
    private int seqGap;
    private int lastSeq;
    private int currentSeq;
    private int currentRssi;
    private double averageRssi;
    private double rssiDiff;
    private int signal;
    private int channel;
    private String timestamp;
}
