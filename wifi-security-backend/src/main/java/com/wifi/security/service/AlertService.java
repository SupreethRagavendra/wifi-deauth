package com.wifi.security.service;

import com.wifi.security.dto.AlertDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class AlertService {

    private static final Logger logger = LoggerFactory.getLogger(AlertService.class);
    private static final int MAX_ALERTS = 500;

    private final CopyOnWriteArrayList<AlertDTO> allAlerts = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<AlertDTO> activeAlerts = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<SseEmitter> emitters = new CopyOnWriteArrayList<>();

    public void processAlert(AlertDTO alert) {
        if (alert.getTimestamp() == null) {
            alert.setTimestamp(Instant.now().toString());
        }


        allAlerts.add(alert);
        activeAlerts.add(alert);

        // Trim
        if (allAlerts.size() > MAX_ALERTS) {
            allAlerts.subList(0, MAX_ALERTS / 2).clear();
        }
        if (activeAlerts.size() > 100) {
            activeAlerts.subList(0, 50).clear();
        }

        logger.warn("🚨 Alert processed: {} - {} (severity: {})",
                alert.getType(), alert.getMessage(), alert.getSeverity());

        // Broadcast to all SSE clients
        broadcastAlert(alert);
    }

    public void broadcastAlert(AlertDTO alert) {
        List<SseEmitter> deadEmitters = new ArrayList<>();

        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event()
                        .name("alert")
                        .data(alert));
            } catch (IOException e) {
                deadEmitters.add(emitter);
            } catch (Exception e) {
                deadEmitters.add(emitter);
            }
        }

        emitters.removeAll(deadEmitters);
        logger.debug("Broadcasted alert to {} clients ({} dead removed)",
                emitters.size(), deadEmitters.size());
    }

    public void broadcastStatus(Map<String, Object> status) {
        List<SseEmitter> deadEmitters = new ArrayList<>();

        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event()
                        .name("status")
                        .data(status));
            } catch (IOException e) {
                deadEmitters.add(emitter);
            } catch (Exception e) {
                deadEmitters.add(emitter);
            }
        }

        emitters.removeAll(deadEmitters);
    }

    public void addEmitter(SseEmitter emitter) {
        emitters.add(emitter);
        logger.info("SSE client connected. Total clients: {}", emitters.size());
    }

    public void removeEmitter(SseEmitter emitter) {
        emitters.remove(emitter);
        logger.info("SSE client disconnected. Total clients: {}", emitters.size());
    }

    public List<AlertDTO> getRecentAlerts() {
        int size = allAlerts.size();
        int from = Math.max(0, size - 50);
        return new ArrayList<>(allAlerts.subList(from, size));
    }

    public List<AlertDTO> getActiveAlerts() {
        return new ArrayList<>(activeAlerts);
    }

    public void clearAlerts() {
        allAlerts.clear();
        activeAlerts.clear();
        logger.info("Cleared all alerts from memory");
    }
}
