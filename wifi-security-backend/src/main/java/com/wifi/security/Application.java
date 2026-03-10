package com.wifi.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * WiFi Security Monitoring Platform - Backend Application
 * 
 * This application provides REST APIs for:
 * - Role-based authentication (Admin, Viewer)
 * - Institute management
 * - WiFi network monitoring
 */
@SpringBootApplication
@org.springframework.scheduling.annotation.EnableScheduling
@org.springframework.scheduling.annotation.EnableAsync
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
