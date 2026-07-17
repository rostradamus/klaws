package com.example;

public class UserService {
    private final UserRepository repository;

    public void register(UserDto user) {
        String s = user.getSsn();
        String msg = "registering id=" + s;
        log.info(msg);
    }

    public void sync(UserDto user) {
        String email = user.getEmail();
        restTemplate.postForObject("https://partner.example.com/sync", email, String.class);
    }
}
