package com.example.order;

import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class OrderEntity {

    @Id
    private Long id;

    private String orderId;

    private String paymentId;

    private int totalAmount;
}
