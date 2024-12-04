package com.backend.auth.services;

import com.backend.auth.entities.RefreshToken;
import com.backend.auth.entities.User;
import com.backend.auth.repositories.RefreshTokenRepository;
import com.backend.auth.repositories.UserRepository;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService {
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(UserRepository userRepository, RefreshTokenRepository refreshTokenRepository) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public RefreshToken createRefeshToken(String username) {
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email" + username));

        RefreshToken refreshToken = user.getRefreshToken();
        if (refreshToken == null) {
//            long refreshTokenValidity = 5*60*60*10000;
            long refreshTokenValidity = 3*1000;
            refreshToken = RefreshToken.builder()
                    .refreshToken(UUID.randomUUID().toString())
                    .expiredTime(Instant.now().plusMillis(refreshTokenValidity))
                    .user(user)
                    .build();
            refreshTokenRepository.save(refreshToken);
        }
        return refreshToken;
    }

    public RefreshToken verifyRefreshToken(String refreshToken) {
        RefreshToken refTokenObj = refreshTokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        if (refTokenObj.getExpiredTime().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(refTokenObj);
            throw new RuntimeException("Refresh token has expired");
        }

        return refTokenObj;
    }
}
