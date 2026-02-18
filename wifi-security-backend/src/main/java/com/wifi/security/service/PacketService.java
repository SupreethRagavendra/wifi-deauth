package com.wifi.security.service;

import com.wifi.security.dto.request.PacketDTO;
import com.wifi.security.entity.CapturedPacket;
import com.wifi.security.repository.PacketRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Service for handling captured packets.
 */
@Service
@RequiredArgsConstructor
public class PacketService {

    private static final Logger log = LoggerFactory.getLogger(PacketService.class);
    private final PacketRepository packetRepository;
    private final com.wifi.security.service.layer1.Layer1Service layer1Service;

    /**
     * Save a batch of captured packets to the database.
     * 
     * @param packets List of packet DTOs to save
     */
    @Transactional
    public void savePackets(List<PacketDTO> packets) {
        log.info("Received {} packets from capture engine", packets.size());

        List<CapturedPacket> entities = packets.stream()
                .map(this::convertToEntity)
                .collect(Collectors.toList());

        packetRepository.saveAll(entities);
        log.info("Saved {} packets to database", entities.size());

        // Trigger asynchronous analysis
        try {
            layer1Service.analyzeBatch(packets);
        } catch (Exception e) {
            log.error("Error triggering detection analysis", e);
        }
    }

    private CapturedPacket convertToEntity(PacketDTO dto) {
        CapturedPacket entity = new CapturedPacket();
        entity.setSourceMac(dto.getSourceMac());
        entity.setDestMac(dto.getDestMac());
        entity.setBssid(dto.getBssid());
        entity.setSequenceNumber(dto.getSequenceNumber());
        entity.setRssi(dto.getRssi());
        entity.setTimestamp(dto.getTimestamp());
        entity.setFrameType(dto.getFrameType());
        return entity;
    }

    /**
     * Retrieve packets captured within the last N minutes.
     * 
     * @param minutes Number of minutes to look back
     * @return List of captured packets
     */
    public List<CapturedPacket> getRecentPackets(int minutes) {
        LocalDateTime since = LocalDateTime.now().minusMinutes(minutes);
        return packetRepository.findRecentPackets(since);
    }
}
