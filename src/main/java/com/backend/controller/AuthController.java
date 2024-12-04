package com.backend.controller;

import com.backend.DTOs.AccountDTO;
import com.backend.mapper.AccountMapper;
import com.backend.model.Account;
import com.backend.model.FacebookUserData;
import com.backend.model.RefreshToken;
import com.backend.model.ResponseError;
import com.backend.records.LoginRequest;
import com.backend.records.LogoutRequest;
import com.backend.records.ROLE;
import com.backend.response.ResponseData;
import com.backend.service.AccountService;
import com.backend.service.RefreshTokenService;
import com.backend.service.RoleService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.sql.SQLOutput;
import java.sql.Timestamp;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;


@Slf4j
@RestController
@RequestMapping(value = "/api/v1/auth")
@AllArgsConstructor
public class AuthController {

  private final Environment env;
  private final AccountService accountService;
  private final PasswordEncoder passwordEncoder;
  private final RoleService roleService;
  private final AuthenticationManager authenticationManager;
  private final RefreshTokenService refreshTokenService;


  /*=======================================MANUAL LOGIN=======================================*/
  @PostMapping("/register")
  public ResponseEntity<ResponseData> register(@RequestBody @Valid Account account) {
    // Hàm tạo một Account mới bên trong hệ thống.
    if (accountService.findAccountByEmail(account.getEmail()) != null || accountService.findAccountByUsername(account.getUsername()) != null)
      return ResponseEntity.status(HttpStatus.CONFLICT.value()).body(new ResponseError(HttpStatus.CONFLICT.value(), "Account already exists"));
    // Không tìm thấy Username. Tạo Account mới.
    account.setRole(roleService.findByRoleName(ROLE.USER));
    account.setPassword(passwordEncoder.encode(account.getPassword()));
    try {
      account = accountService.save(account);
    } catch (RuntimeException e) {
      log.error("Failed to create user: {}", account.getUsername(), e);
      return ResponseEntity.status(HttpStatus.CONTINUE.value()).body(new ResponseError(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Failed to register a new user"));
    }

    if (account.getId() > 0) {
      return ResponseEntity.status(HttpStatus.OK).body(new ResponseData(HttpStatus.CREATED.value(), "Created successfully", null));
    }
    return ResponseEntity.internalServerError().body(new ResponseError(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Failed to register a new user"));
  }

  @PostMapping("/login")
  public ResponseEntity<ResponseData> login(@RequestBody LoginRequest loginRequest) {
    String accessToken = "";
    String content = "";
    Authentication authentication = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.username(), loginRequest.password());
    Authentication authenticationResponse = authenticationManager.authenticate(authentication); // Thực hiện authenticate bằng cách dùng @Bean Manager đã tạo trong ProjectConfigSecurity để xác thực.

    AccountDTO dto = null;
    if (null != authenticationResponse && authenticationResponse.isAuthenticated()) {
      if (null != env) {
        // Thực hiện việc tạo access-token và refresh-token.

        String username = authenticationResponse.getName();
        content = RefreshTokenService.generateRefreshToken(username); // Vì mã hoá thông tin dựa vào username nên chuỗi mã hoá mặc định là duy nhất.

        RefreshToken token = refreshTokenService.findByContent(content);
        if (token == null) {
          token = new RefreshToken();
          token.setContent(content);
          token.setUsername(username);
          token.setValidUntil(new Timestamp(new Date(new Date().getTime() + 30 * 24 * 3600 * 1000L).getTime()));  // Có thời hạn 30 ngày.
        }
        String secret = env.getProperty("SECRET_KEY");
        SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        accessToken = Jwts.builder().setIssuer("Authorization service").setSubject("Access Token")
                .claim("username", authenticationResponse.getName())
                .claim("roles", authenticationResponse.getAuthorities().stream().map(
                        GrantedAuthority::getAuthority).collect(Collectors.joining(",")))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + 7 * 24 * 3600 * 1000L))
                .signWith(secretKey).compact();
        token.setAccessToken(accessToken);
        refreshTokenService.save(token);
      } else log.error("COULD NOT FIND ENVIRONMENT VARIABLE!");
    } else {
      log.error("UNAUTHENTICATED USER!");
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ResponseError(HttpStatus.UNAUTHORIZED.value(), "Unauthorized"));
    }

    // Thống nhất là sẽ chỉ gửi access-token và refresh-token ở cookies. access-token sẽ có thời hạn là 7 days, refresh-token là 15 days.
//    ResponseCookie refreshCookie = ResponseCookie.from("refresh_token").value(content).httpOnly(true).path("/").maxAge(30 * 24 * 3600L).build();

    // Gửi về cho Client access-token và refresh-token.
    return ResponseEntity.ok().body(new ResponseData(HttpStatus.OK.value(), "Login successfully", Map.of("token_type", "Bearer", "access_token", accessToken, "expires_in", new Timestamp(new Date().getTime() + 7 * 24 * 3600 * 1000L), "refresh_token", content)));
  }

  // Tạo ra API để refresh access token.
  @GetMapping("/refresh-token")
  public ResponseEntity<ResponseData> refreshToken(HttpServletRequest request, @RequestBody String refreshToken) {
    // Giả sử refresh token ở trong payload và access token ở trong header.
    String value = request.getHeader("Authorization");
    String accessToken = value.substring(7); // Bỏ qua Bearer.

    // Xác thực xem access-token đã hết hạn hay chưa.
    RefreshToken token = null;
    String secret = env.getProperty("SECRET_KEY");
    SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    boolean isExpired = false;

    try {
      Claims claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(accessToken.toString()).getBody();
    } catch (ExpiredJwtException e) {
      // Token thực sự hết hạn.
      log.warn("Access token has truly expired");
      token = refreshTokenService.findByContent(refreshToken.toString());
      isExpired = token.getAccessToken().contentEquals(accessToken);
    } catch (RuntimeException e) {
      throw new RuntimeException("Validate JWT token failed!");
    }
    if (!isExpired) {
      return ResponseEntity.status(HttpStatus.OK).body(new ResponseError(HttpStatus.FORBIDDEN.value(), "Access token didn't expire!"));
    }
    // Phải xét 2 trường hợp: refresh token còn hạn và refresh token hết hạn.

    // 1. Xét trường hợp refresh token còn hạn.
    Timestamp current = new Timestamp(new Date().getTime());
    if (token.getId() > 0 && token.getValidUntil().getTime() > current.getTime()) {
      // Trả về cho Client một access-token mới.
      AccountDTO dto = accountService.findAccountDTOByUsername(token.getUsername());
      String jwt = Jwts.builder().setIssuer("Backend Advanced Web").setSubject("Access Token")
              .claim("username", dto.getUsername())
              .claim("roles", dto.getRole())
              .setIssuedAt(new Date())
              .setExpiration(new Date((new Date()).getTime() + 7 * 24 * 3600 * 1000L))
              .signWith(secretKey).compact();

      // Update lại jwt ở Tokens trong DB.
      token.setAccessToken(jwt);
      return ResponseEntity.ok(new ResponseData(HttpStatus.OK.value(), "Issued a new access token!", Map.of("token_type", "Bearer", "access_token", jwt, "expires_in", new Timestamp(new Date().getTime() + 7 * 24 * 3600 * 1000L))));
    }
    // 2. Xét trường hợp là hết hạn, xoá refresh token dưới DB rồi sau đó trả về response yêu cầu Client đăng nhập lại.
    refreshTokenService.deleteRefreshTokenByContent(refreshToken.toString());
    // deleted successfully.
    return ResponseEntity.status(HttpStatus.OK).body(new ResponseError(HttpStatus.UNAUTHORIZED.value(), "refresh token is expired, please login again!"));
  }

  @PostMapping("/logout")
  public ResponseEntity<ResponseData> logout(HttpServletRequest request, @RequestBody LogoutRequest logoutRequest) {
    RefreshToken token = refreshTokenService.findByContent(logoutRequest.refreshToken());
    if (token != null && token.getId() > 0) {
      refreshTokenService.delete(token);
    }
    // Nếu tìm thấy token thì xoá access token có liên quan.
    String value = request.getHeader("Authorization");
    String accessToken = value.substring(7);
    if (accessToken.isEmpty())
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ResponseError(HttpStatus.BAD_REQUEST.value(), "Can't logout!"));
    return ResponseEntity.ok().body(new ResponseData(HttpStatus.OK.value(), "Logout successfully!", null));
  }


  /*=======================================SOCIAL LOGIN=======================================*/
  @PostMapping(value = "/facebook-login")
  public ResponseEntity<ResponseData> loginWithFacebook(@RequestBody FacebookUserData data) {
    // Kiểm tra xem id đã tồn tại hay chưa.
    String id = data.getId();
    Account account = accountService.findAccountByUsername(id);
    if (account == null) {
      // Tạo mới một Account.
      account = new Account();
      account.setUsername(id);
      account.setName(data.getName());
      account.setEmail(data.getEmail());
      account.setRole(roleService.findByRoleName(ROLE.USER));
      account.setPassword(passwordEncoder.encode("123456"));
      account = accountService.save(account);
    }


    // Tới đây thì đã có account. Thống nhất là chỉ gửi access-token cho người dùng loại này.
    try {
      String secret = env.getProperty("SECRET_KEY");
      SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
      // Chỉ tạo ra access-token cho người dùng loại này. Hết hạn thì phải đăng nhập lại hệ thống.
      String jwt = Jwts.builder().setIssuer("Web Recommendation").setSubject("Access Token")
              .claim("username", account.getUsername())
              .claim("authorities", "USER")
              .setIssuedAt(new Date())
              .setExpiration(new Date((new Date()).getTime() + 24 * 3600 * 1000L))
              .signWith(secretKey).compact();
      return ResponseEntity.ok(new ResponseData(HttpStatus.OK.value(), "Login successfully", Map.of("token_type", "Bearer", "access_token", jwt, "expires_in", new Timestamp(new Date().getTime() + 24 * 3600 * 1000L)))); // Cho thời gian của đăng nhập bằng Social ít hơn thông thường.
    } catch (RuntimeException e) {
      return ResponseEntity.ok(new ResponseError(HttpStatus.BAD_REQUEST.value(), "Internal Server Error"));
    }
  }

  /*=======================================USER PROFILE=======================================*/
  @GetMapping(value = "/profile")
  public ResponseEntity<ResponseData> getProfile(HttpServletRequest request) {
    String value = request.getHeader("Authorization");
    String accessToken = value.substring(7);
    Claims claims = Jwts.parserBuilder().setSigningKey(Keys.hmacShaKeyFor(env.getProperty("SECRET_KEY").getBytes(StandardCharsets.UTF_8))).build().parseClaimsJws(accessToken).getBody();
    String username = claims.get("username", String.class);
    Account saved = accountService.findAccountByUsername(username);
    if (saved != null && saved.getId() > 0) {
      return ResponseEntity.ok(new ResponseData(HttpStatus.OK.value(), "Profile found", saved));
    }
    return ResponseEntity.notFound().build();
  }
}
