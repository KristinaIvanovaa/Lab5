package com.example.demo.repository;

import java.util.Optional;
import java.util.UUID;

import com.example.demo.model.UserSession;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserSessionRepository extends JpaRepository<UserSession, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from UserSession s where s.refreshToken = :refreshToken")
    Optional<UserSession> findByRefreshTokenForUpdate(@Param("refreshToken") String refreshToken);
}
