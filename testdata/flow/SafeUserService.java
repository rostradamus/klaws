package com.example;

public class SafeUserService {
    public void register(UserDto user) {
        String masked = mask(user.getSsn());
        log.info("registering id=" + masked);
    }

    public void describe() {
        log.info("this method mentions ssn and email in a literal only");
    }
}
