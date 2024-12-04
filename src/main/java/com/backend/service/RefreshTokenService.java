package com.backend.service;

import com.backend.model.RefreshToken;
import com.backend.repository.RefreshTokenRepo;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Service
@AllArgsConstructor
public class RefreshTokenService {

  private final RefreshTokenRepo refreshTokenRepo;

  private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding(); // Encoder Base64 để chuyển đổi thành chuỗi

  public static String generateRefreshToken(String username) {
    return base64Encoder.encodeToString(username.getBytes());
  }

  public RefreshToken findByContent(String content) {
    return refreshTokenRepo.findByContent(content);
  }

  public void save(RefreshToken token) {
    refreshTokenRepo.save(token);
  }

  public void deleteRefreshTokenByContent(String content) {
    refreshTokenRepo.deleteByContent(content);
  }

  public void delete(RefreshToken token) {
    refreshTokenRepo.delete(token);
  }

  public RefreshToken findByAccessToken(String accessToken) {
    return refreshTokenRepo.findByAccessToken(accessToken);
  }
}
