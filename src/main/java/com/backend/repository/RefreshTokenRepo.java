package com.backend.repository;

import com.backend.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenRepo extends JpaRepository<RefreshToken, Integer> {
  RefreshToken findByContent(String content);
  RefreshToken findByAccessToken(String accessToken);
  void deleteByContent(String content);
}
