package com.wifi.security.dto.request;

import lombok.Data;
import java.time.LocalDateTime;

@Data
public class PacketDTO {
    private String sourceMac;
    private String destMac;
    private String bssid;
    private Integer sequenceNumber;
    private Integer rssi;
    private LocalDateTime timestamp;
    private String frameType;
    private String realAttackerMac;
    private Boolean isSpoofed;
}
