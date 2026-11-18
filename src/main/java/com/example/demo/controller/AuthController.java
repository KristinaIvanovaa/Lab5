package com.example.demo.controller;

import java.util.Map;

import com.example.demo.dto.LoginRequest;
import com.example.demo.dto.RefreshRequest;
import com.example.demo.dto.RegistrationRequest;
import com.example.demo.dto.TokenPairResponse;
import com.example.demo.exception.UnauthorizedException;
import com.example.demo.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    private final AuthService auth;

    public AuthController(AuthService auth) {
        this.auth = auth;
    }

    @GetMapping("/api/auth/csrf")
    public Map<String, String> csrf(CsrfToken csrfToken) {
        return Map.of("headerName", csrfToken.getHeaderName(), "token", csrfToken.getToken());
    }

    @PostMapping("/auth/login")
    public ResponseEntity<TokenPairResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthService.AuthResult result = auth.login(request);
        return tokenResponse(HttpStatus.OK, result);
    }

    @PostMapping({"/auth/register", "/api/auth/register"})
    public ResponseEntity<TokenPairResponse> register(@Valid @RequestBody RegistrationRequest request) {
        return tokenResponse(HttpStatus.CREATED, auth.register(request));
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<TokenPairResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        AuthService.AuthResult result = auth.refresh(request.refreshToken())
                .orElseThrow(() -> new UnauthorizedException("Invalid or expired refresh token"));
        return tokenResponse(HttpStatus.OK, result);
    }

    private ResponseEntity<TokenPairResponse> tokenResponse(HttpStatus status, AuthService.AuthResult result) {
        return ResponseEntity.status(status)
                .header("Authorization", "Bearer " + result.accessToken())
                .body(new TokenPairResponse(result.id(), result.accessToken(), result.refreshToken()));
    }
}
