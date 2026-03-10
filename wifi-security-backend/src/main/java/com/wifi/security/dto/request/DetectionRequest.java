package com.wifi.security.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Detection Request DTO for Layer 1 analysis.
 * Contains all necessary frame data for anomaly detection.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DetectionRequest {

    /**
     * Unique request identifier for tracking and correlation.
     */
    private String requestId;

    /**
     * Source MAC address of the frame sender.
     * Must be in standard MAC format (XX:XX:XX:XX:XX:XX).
     */
    @NotBlank(message = "Source MAC address is required")
    @Pattern(regexp = "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", message = "Invalid MAC address format")
    private String sourceMac;

    /**
     * Destination MAC address of the frame.
     */
    @Pattern(regexp = "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$|^$", message = "Invalid MAC address format")
    private String destMac;

    /**
     * BSSID (AP MAC address) of the target network.
     */
    @NotBlank(message = "BSSID is required")
    @Pattern(regexp = "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", message = "Invalid BSSID format")
    private String bssid;

    /**
     * 802.11 frame type (e.g., DEAUTH, DISASSOC, AUTH, etc.)
     */
    private String frameType;
    private String realAttackerMac;
    private Boolean isSpoofed;

    /**
     * 802.11 sequence number (0-4095).
     */
    private Integer sequenceNumber;

    /**
     * RSSI (signal strength) value.
     */
    private Integer rssi;

    /**
     * Timestamp of frame capture.
     */
    private LocalDateTime timestamp;

    /**
     * Network identifier (institute/organization ID).
     */
    private String networkId;

    /**
     * Priority indicator for processing.
     * Higher priority requests are processed first.
     */
    @Builder.Default
    private Integer priority = 0;

    /**
     * Flag to indicate if this is a real-time streaming request.
     */
    @Builder.Default
    private boolean realtime = true;
}
