package com.example.payment;

import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class PaymentEntity {

    @Id
    private Long id;

    // Stored in plaintext — no protection applied.
    private String cardNumber;

    private String accountNumber;

    @Encrypted
    private String cvv;
}
