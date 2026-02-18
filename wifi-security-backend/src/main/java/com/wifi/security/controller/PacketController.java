package com.wifi.security.controller;

import com.wifi.security.dto.DeauthPacketDTO;
import com.wifi.security.dto.BatchPacketDTO;
import com.wifi.security.service.DetectionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/packets")
@CrossOrigin(origins = "*")
public class PacketController {

    private static final Logger logger = LoggerFactory.getLogger(PacketController.class);

    @Autowired
    private DetectionService detectionService;

    @PostMapping("/deauth")
    public ResponseEntity<?> receiveDeauthPacket(@RequestBody DeauthPacketDTO packet) {
        logger.info("Received deauth packet: SRC={} DST={} BSSID={} Signal={}dBm",
                packet.getSrc(), packet.getDst(), packet.getBssid(), packet.getSignal());

        detectionService.processPacket(packet);

        return ResponseEntity.ok(Map.of(
                "status", "received",
                "processed", true));
    }

    @PostMapping("/deauth/batch")
    public ResponseEntity<?> receiveBatch(@RequestBody BatchPacketDTO batch) {
        logger.info("Received batch of {} packets", batch.getPackets().size());

        detectionService.processBatch(batch.getPackets());

        return ResponseEntity.ok(Map.of(
                "status", "batch_received",
                "count", batch.getPackets().size()));
    }
}
