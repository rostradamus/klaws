package com.example.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserService {
    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    public void registerUser(String name, String email) {
        // This should be flagged — email in log
        log.info("User registered: " + email);

        // This should be flagged — phone in log
        log.debug("Phone number: {}", phone);

        // This should NOT be flagged — no personal data
        log.info("User registration completed successfully");

        // This should be flagged — password in log
        log.warn("Login failed for password: " + password);
    }
}
