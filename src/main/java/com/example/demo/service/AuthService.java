package com.example.demo.service;

import java.time.Instant;
import java.util.Optional;

import com.example.demo.dto.LoginRequest;
import com.example.demo.dto.RegistrationRequest;
import com.example.demo.exception.UnauthorizedException;
import com.example.demo.model.SessionStatus;
import com.example.demo.model.User;
import com.example.demo.model.UserSession;
import com.example.demo.repository.UserRepository;
import com.example.demo.repository.UserSessionRepository;
import com.example.demo.security.JwtTokenService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {
    private final UserService users;
    private final UserRepository userRepository;
    private final UserSessionRepository sessions;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwt;

    public AuthService(UserService users, UserRepository userRepository,
            UserSessionRepository sessions, PasswordEncoder passwordEncoder, JwtTokenService jwt) {
        this.users = users;
        this.userRepository = userRepository;
        this.sessions = sessions;
        this.passwordEncoder = passwordEncoder;
        this.jwt = jwt;
    }

    @Transactional
    public AuthResult login(LoginRequest request) {
        String email = request.email().trim().toLowerCase(java.util.Locale.ROOT);
        User user = userRepository.findByEmailIgnoreCase(email)
                .filter(account -> account.isEnabled() && passwordEncoder.matches(request.password(),
                        account.getPasswordHash()))
                .orElseThrow(() -> new UnauthorizedException("Invalid email or password"));
        return issue(user, request.deviceId());
    }

    @Transactional
    public AuthResult register(RegistrationRequest request) {
        User user = users.register(request);
        return issue(user, request.deviceId());
    }

    @Transactional
    public Optional<AuthResult> refresh(String refreshToken) {
        JwtTokenService.TokenClaims claims = jwt.validateRefreshToken(refreshToken);
        UserSession session = sessions.findByRefreshTokenForUpdate(refreshToken).orElse(null);
        if (session == null) {
            return Optional.empty();
        }

        Instant now = Instant.now();
        if (session.getStatus() == SessionStatus.USED) {
            if (session.getRefreshTokenExpiry() != null && session.getRefreshTokenExpiry().isAfter(now)) {
                session.setStatus(SessionStatus.REVOKED);
                sessions.save(session);
            }
            return Optional.empty();
        }
        if (session.getStatus() != SessionStatus.ACTIVE
                || session.getRefreshTokenExpiry() == null
                || !session.getRefreshTokenExpiry().isAfter(now)
                || !session.getUsername().equals(claims.subject())) {
            return Optional.empty();
        }

        User user = userRepository.findByEmailIgnoreCase(session.getUsername())
                .filter(account -> account.isEnabled()
                        && account.getEmail().equals(claims.subject()))
                .orElse(null);
        if (user == null) {
            return Optional.empty();
        }

        session.setStatus(SessionStatus.USED);
        sessions.save(session);
        return Optional.of(issue(user, session.getDeviceId()));
    }

    private AuthResult issue(User user, String deviceId) {
        JwtTokenService.IssuedToken access = jwt.createAccessToken(user.getEmail());
        JwtTokenService.IssuedToken refresh = jwt.createRefreshToken(user.getEmail());
        sessions.save(new UserSession(user.getEmail(), deviceId, access.value(), refresh.value(),
                access.expiresAt(), refresh.expiresAt(), SessionStatus.ACTIVE));
        return new AuthResult(user.getId(), access.value(), refresh.value());
    }

    public record AuthResult(Long id, String accessToken, String refreshToken) { }
}
