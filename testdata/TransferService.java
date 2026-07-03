package com.example.transfer;

public class TransferService {

    private final RestTemplate restTemplate;

    public TransferService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void share(String email, String phoneNumber) {
        String url = "https://partner.example.com/api/import";
        restTemplate.postForObject(url, new Payload(email, phoneNumber), Void.class);
    }
}
