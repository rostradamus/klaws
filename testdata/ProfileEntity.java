package com.example.profile;

import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class ProfileEntity {

    @Id
    private Long id;

    private String email;

    private String phoneNumber;
}
