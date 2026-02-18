package com.wifi.security.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class DeauthPacketDTO {
    private String src;
    private String dst;
    private String bssid;
    private int reason;
    private Integer signal;
    private int channel;
    private int seq;
    private String frameType;
    private int subtype;
    private String timestamp;
    private String interfaceName;
    private boolean test;
}
