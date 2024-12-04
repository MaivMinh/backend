package com.backend.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthenticationEvents {
  @EventListener
  public void onSuccess(AuthenticationSuccessEvent event) {
    log.info("Login successfully for user: {}", event.getAuthentication().getName().toUpperCase());
  }

  @EventListener
  public void onFailure(AbstractAuthenticationFailureEvent event) {
    log.error("Login failed for user: {} due to {}", event.getAuthentication().getName().toUpperCase(), event.getException().getMessage());
  }
}
