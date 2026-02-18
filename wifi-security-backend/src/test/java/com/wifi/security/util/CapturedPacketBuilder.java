package com.wifi.security.util;

import com.wifi.security.entity.CapturedPacket;
import java.time.LocalDateTime;

public class CapturedPacketBuilder {
    private String id;
    private String sourceMac = "00:11:22:33:44:55";
    private String destMac = "AA:BB:CC:DD:EE:FF";
    private String bssid = "11:22:33:44:55:66";
    private Integer sequenceNumber = 100;
    private Integer rssi = -60;
    private LocalDateTime timestamp = LocalDateTime.now();
    private String frameType = "Deauth";

    public CapturedPacketBuilder withId(String id) {
        this.id = id;
        return this;
    }

    public CapturedPacketBuilder withSourceMac(String sourceMac) {
        this.sourceMac = sourceMac;
        return this;
    }

    public CapturedPacketBuilder withDestMac(String destMac) {
        this.destMac = destMac;
        return this;
    }

    public CapturedPacketBuilder withBssid(String bssid) {
        this.bssid = bssid;
        return this;
    }

    public CapturedPacketBuilder withSequenceNumber(Integer sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
        return this;
    }

    public CapturedPacketBuilder withRssi(Integer rssi) {
        this.rssi = rssi;
        return this;
    }

    public CapturedPacketBuilder withTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
        return this;
    }

    public CapturedPacketBuilder withFrameType(String frameType) {
        this.frameType = frameType;
        return this;
    }

    public CapturedPacket build() {
        CapturedPacket packet = new CapturedPacket();
        packet.setId(id);
        packet.setSourceMac(sourceMac);
        packet.setDestMac(destMac);
        packet.setBssid(bssid);
        packet.setSequenceNumber(sequenceNumber);
        packet.setRssi(rssi);
        packet.setTimestamp(timestamp);
        packet.setFrameType(frameType);
        return packet;
    }
}
