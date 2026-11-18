package com.example.demo.model;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "user_sessions")
public class UserSession {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, length = 254)
    private String username;

    @Column(name = "device_id", columnDefinition = "TEXT")
    private String deviceId;

    @Column(name = "access_token", nullable = false, columnDefinition = "TEXT")
    private String accessToken;

    @Column(name = "refresh_token", nullable = false, unique = true, columnDefinition = "TEXT")
    private String refreshToken;

    @Column(name = "access_token_expiry", nullable = false)
    private Instant accessTokenExpiry;

    @Column(name = "refresh_token_expiry", nullable = false)
    private Instant refreshTokenExpiry;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private SessionStatus status;

    protected UserSession() {
    }

    public UserSession(String username, String deviceId, String accessToken, String refreshToken,
            Instant accessTokenExpiry, Instant refreshTokenExpiry, SessionStatus status) {
        this.username = username;
        this.deviceId = deviceId;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.accessTokenExpiry = accessTokenExpiry;
        this.refreshTokenExpiry = refreshTokenExpiry;
        this.status = status;
    }

    public UUID getId() { return id; }
    public String getUsername() { return username; }
    public String getDeviceId() { return deviceId; }
    public String getAccessToken() { return accessToken; }
    public String getRefreshToken() { return refreshToken; }
    public Instant getAccessTokenExpiry() { return accessTokenExpiry; }
    public Instant getRefreshTokenExpiry() { return refreshTokenExpiry; }
    public SessionStatus getStatus() { return status; }
    public void setStatus(SessionStatus status) { this.status = status; }
}
