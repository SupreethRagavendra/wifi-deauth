package com.wifi.security.service.layer3;

import com.wifi.security.dto.DeauthPacketDTO;
import com.wifi.security.dto.response.DetectionResponse;
import com.wifi.security.dto.response.Layer2Response;
import com.wifi.security.dto.response.Layer3Response;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class Layer3Service {

    // attackerMac -> Set of targetMacs
    private final ConcurrentHashMap<String, Set<String>> multiClientTracker = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> lastSeenTracker = new ConcurrentHashMap<>();

    public Layer3Response analyze(DeauthPacketDTO packet, DetectionResponse l1, Layer2Response l2) {
        int rssiScore = 0;
        int multiClientScore = 0;
        int broadcastScore = 0;
        StringBuilder notes = new StringBuilder();

        // 1. RSSI Sanity Check
        int rssi = packet.getSignal() != null ? packet.getSignal() : -100;
        if (rssi == -100) {
            rssiScore = 20;
            notes.append("Signal strength missing (likely a fake device). ");
        } else if (rssi >= -50 && rssi <= -30) {
            rssiScore = 30;
            notes.append("Signal is suspiciously strong. ");
        } else if (rssi >= -70 && rssi < -50) {
            rssiScore = 15;
            notes.append("Signal strength looks unusual. ");
        } else if (rssi < -85) {
            rssiScore = 0;
            notes.append("Signal is very weak (likely normal). ");
        }

        // 2. Multi-client Pattern
        long now = System.currentTimeMillis();
        String attackerMac = packet.getSrc();
        String targetMac = packet.getDst();

        // Clean entries older than 10 seconds
        multiClientTracker.keySet().removeIf(mac -> now - lastSeenTracker.getOrDefault(mac, 0L) > 10000);

        if (attackerMac != null && targetMac != null) {
            multiClientTracker.computeIfAbsent(attackerMac, k -> ConcurrentHashMap.newKeySet()).add(targetMac);
            lastSeenTracker.put(attackerMac, now);

            int targetCount = multiClientTracker.get(attackerMac).size();
            if (targetCount >= 3) {
                multiClientScore = 25;
                notes.append(String.format("Device is attacking multiple targets at once (%d targets). ", targetCount));
            } else if (targetCount == 2) {
                multiClientScore = 15;
                notes.append("Device is attacking multiple targets at once (2 targets). ");
            } else {
                multiClientScore = 0;
            }
        }

        // 3. Broadcast Check
        if ("FF:FF:FF:FF:FF:FF".equalsIgnoreCase(targetMac)) {
            broadcastScore = 15;
            notes.append("Attacking all devices on the network. ");
        }

        int physicalScore = Math.min(70, rssiScore + multiClientScore + broadcastScore);

        return Layer3Response.builder()
                .physicalScore(physicalScore)
                .rssiScore(rssiScore)
                .multiClientScore(multiClientScore)
                .broadcastScore(broadcastScore)
                .analysisNotes(notes.toString().trim())
                .build();
    }
}
