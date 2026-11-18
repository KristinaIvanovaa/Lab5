package com.example.demo.security;

import java.io.IOException;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenService jwt;
    private final UserRepository users;

    public JwtAuthenticationFilter(JwtTokenService jwt, UserRepository users) {
        this.jwt = jwt;
        this.users = users;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.equals("/auth/login")
                || path.equals("/auth/register")
                || path.equals("/auth/refresh")
                || path.equals("/api/auth/register");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            try {
                JwtTokenService.TokenClaims claims = jwt.validateAccessToken(authorization.substring(7));
                User user = users.findByEmailIgnoreCase(claims.subject()).orElse(null);
                if (user == null || !user.isEnabled()) {
                    reject(response);
                    return;
                }
                var authentication = new UsernamePasswordAuthenticationToken(
                        user.getEmail(), null,
                        java.util.List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name())));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (JwtTokenService.InvalidTokenException exception) {
                reject(response);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private void reject(HttpServletResponse response) throws IOException {
        SecurityContextHolder.clearContext();
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"Invalid or expired access token\"}");
    }
}
