package com.backend.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.sql.Timestamp;

@Entity
@Getter
@Setter
@Table(name = "refresh_tokens")
public class RefreshToken {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Integer id;
  private String content;

  @Column(name = "access_token")
  private String accessToken;

  @Column(name = "valid_until")
  private Timestamp validUntil;
  private String username;
}
