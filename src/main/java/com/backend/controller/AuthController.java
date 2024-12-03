package com.backend.controller;

import com.backend.model.FacebookUserData;
import com.backend.model.ResponseError;
import com.backend.response.ResponseData;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;


@Slf4j
@RestController
@AllArgsConstructor
@RequestMapping(value = "/api/v1/auth")
public class AuthController {

  private final Environment env;

  @PostMapping(value = "/facebook-login")
  public ResponseEntity<ResponseData> loginWithFacebook(@RequestBody FacebookUserData data ) {
    try {
      String secret = env.getProperty("SECRET_KEY");
      SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
      // Chỉ tạo ra access-token cho người dùng loại này. Hết hạn thì phải đăng nhập lại hệ thống.
      String jwt = Jwts.builder().setIssuer("Web Recommendation").setSubject("Access Token")
              .claim("username", data.getEmail())
              .claim("authorities", "ROLE_USER")
              .setIssuedAt(new Date())
              .setExpiration(new Date((new Date()).getTime() + 3 * 24 * 3600 * 1000L))
              .signWith(secretKey).compact();
      return ResponseEntity.ok(new ResponseData(HttpStatus.OK.value(), "Login successfully", Map.of("token_type", "Bearer", "access_token", jwt, "expires_in", new Timestamp(new Date().getTime() + 3 * 24 * 3600 * 1000L)))); // Cho thời gian của đăng nhập bằng Social ít hơn thông thường.
    } catch (RuntimeException e) {
      return ResponseEntity.ok(new ResponseError(HttpStatus.BAD_REQUEST.value(), "Internal Server Error"));
    }
  }
}
