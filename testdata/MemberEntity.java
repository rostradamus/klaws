package com.example.entity;

import javax.persistence.Entity;
import javax.persistence.Column;

@Entity
public class MemberEntity {

    // Should be flagged — plain String for resident number
    @Column
    private String residentNumber;

    // Should NOT be flagged — has @Encrypted
    @Encrypted
    @Column
    private String ssn;

    // Should be flagged — 주민번호 without encryption
    private String 주민번호;

    // Should NOT be flagged — encrypt() called nearby
    private String residentNo;

    public void setResidentNo(String value) {
        this.residentNo = encrypt(value);
    }

    // Should NOT be flagged — not a sensitive field
    private String username;
}
