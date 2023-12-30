package com.signupandlogin.jwtauthentication.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Table(name = "_otp_")
@Entity
public class Otp{
    @Id
    private String email;
    private String otp;
    private LocalDateTime expiryTime;
}