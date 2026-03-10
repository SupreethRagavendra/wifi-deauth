package com.wifi.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO carrying attack alert data for email/SMS notifications.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AttackAlertData {
    private String attackerMac;
    private String victimMac;
    private double confidence;
    private String ssid;
    private String timestamp;
    private String defenseLevel;
    private String status;
    private String channel;
}
