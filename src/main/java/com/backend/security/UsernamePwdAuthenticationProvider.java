package com.backend.security;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
@AllArgsConstructor
public class UsernamePwdAuthenticationProvider implements AuthenticationProvider {
  private final OwnUserDetailsService detailsService;
  private final PasswordEncoder passwordEncoder;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    // Hàm thực hiện xác thực {username, password} của User khi thực hiện Sign-In.
    String username = authentication.getName();
    String rawPassword = authentication.getCredentials().toString();
    try {
      UserDetails userDetails = detailsService.loadUserByUsername(username);
      boolean isMatched = passwordEncoder.matches(rawPassword, userDetails.getPassword());
      if (isMatched) {
        return new UsernamePasswordAuthenticationToken(username, userDetails.getPassword(), userDetails.getAuthorities());
      } else {
        log.info("PASSWORD DOESN'T MATCH!");
        return new UsernamePasswordAuthenticationToken(username, rawPassword);
      }

    } catch (UsernameNotFoundException e1) {
      log.error(e1.getMessage());
      throw e1;
    } catch (Exception e) {
      log.error("Failed to authenticate user with email: {}", username, e);
      throw new AuthenticationException("Authentication failed!") {
      };
    }
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
