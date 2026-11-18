package com.example.demo.security;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtTokenService {
    private final ObjectMapper objectMapper;
    private final byte[] signingKey;
    private final long accessTokenTtlSeconds;
    private final long refreshTokenTtlSeconds;

    public JwtTokenService(ObjectMapper objectMapper,
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.access-token-ttl-seconds}") long accessTokenTtlSeconds,
            @Value("${security.jwt.refresh-token-ttl-seconds}") long refreshTokenTtlSeconds) {
        if (secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalArgumentException("JWT secret must be at least 32 bytes");
        }
        if (accessTokenTtlSeconds <= 0 || refreshTokenTtlSeconds <= 0) {
            throw new IllegalArgumentException("JWT token lifetimes must be positive");
        }
        this.objectMapper = objectMapper;
        this.signingKey = secret.getBytes(StandardCharsets.UTF_8);
        this.accessTokenTtlSeconds = accessTokenTtlSeconds;
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    }

    public IssuedToken createAccessToken(String subject) {
        return createToken(subject, "access", accessTokenTtlSeconds);
    }

    public IssuedToken createRefreshToken(String subject) {
        return createToken(subject, "refresh", refreshTokenTtlSeconds);
    }

    public TokenClaims validateAccessToken(String token) {
        return validate(token, "access");
    }

    public TokenClaims validateRefreshToken(String token) {
        return validate(token, "refresh");
    }

    private IssuedToken createToken(String subject, String type, long ttlSeconds) {
        Instant issuedAt = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        Instant expiresAt = issuedAt.plusSeconds(ttlSeconds);
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", subject);
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iat", issuedAt.getEpochSecond());
        claims.put("exp", expiresAt.getEpochSecond());
        claims.put("type", type);
        try {
            String header = encode(objectMapper.writeValueAsBytes(Map.of("alg", "HS256", "typ", "JWT")));
            String payload = encode(objectMapper.writeValueAsBytes(claims));
            String unsignedToken = header + "." + payload;
            return new IssuedToken(unsignedToken + "." + encode(sign(unsignedToken)), expiresAt);
        } catch (JacksonException | GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to create JWT", exception);
        }
    }

    private TokenClaims validate(String token, String expectedType) {
        if (token == null) {
            throw new InvalidTokenException();
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new InvalidTokenException();
        }
        try {
            Map<String, Object> header = objectMapper.readValue(
                    Base64.getUrlDecoder().decode(parts[0]), new TypeReference<>() { });
            if (!"HS256".equals(header.get("alg")) || !"JWT".equals(header.get("typ"))) {
                throw new InvalidTokenException();
            }
            byte[] expectedSignature = sign(parts[0] + "." + parts[1]);
            byte[] actualSignature = Base64.getUrlDecoder().decode(parts[2]);
            if (!MessageDigest.isEqual(expectedSignature, actualSignature)) {
                throw new InvalidTokenException();
            }
            Map<String, Object> claims = objectMapper.readValue(
                    Base64.getUrlDecoder().decode(parts[1]), new TypeReference<>() { });
            Object subject = claims.get("sub");
            Object id = claims.get("jti");
            Object issueTime = claims.get("iat");
            Object expiration = claims.get("exp");
            if (!(subject instanceof String subjectValue) || subjectValue.isBlank()
                    || !(id instanceof String idValue) || idValue.isBlank()
                    || !(issueTime instanceof Number issuedAt)
                    || !(expiration instanceof Number expiresAt)
                    || !expectedType.equals(claims.get("type"))
                    || expiresAt.longValue() <= Instant.now().getEpochSecond()
                    || issuedAt.longValue() > Instant.now().getEpochSecond()) {
                throw new InvalidTokenException();
            }
            return new TokenClaims(subjectValue, idValue, Instant.ofEpochSecond(expiresAt.longValue()));
        } catch (JacksonException | IllegalArgumentException | GeneralSecurityException exception) {
            throw new InvalidTokenException();
        }
    }

    private byte[] sign(String value) throws GeneralSecurityException {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(signingKey, "HmacSHA256"));
        return mac.doFinal(value.getBytes(StandardCharsets.US_ASCII));
    }

    private String encode(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    public record IssuedToken(String value, Instant expiresAt) { }
    public record TokenClaims(String subject, String id, Instant expiresAt) { }

    public static class InvalidTokenException extends RuntimeException {
        public InvalidTokenException() {
            super("Invalid or expired token");
        }
    }
}
