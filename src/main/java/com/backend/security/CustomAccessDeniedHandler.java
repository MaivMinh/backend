package com.backend.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.time.LocalDateTime;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {
  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
    accessDeniedException.printStackTrace();
    String timeStamp = LocalDateTime.now().toString();
    String message = (accessDeniedException != null && accessDeniedException.getMessage() != null) ? accessDeniedException.getMessage() : "Authorization failed!";
    String path = request.getRequestURI();
    response.setStatus(HttpStatus.FORBIDDEN.value());
    response.setContentType("application/json");
    response.setHeader("application-denied-reason", "Authorization failed");
    String jsonResponse = String.format("{" +
            "\"timestamp\":" + "\"%s\"\n" +
            "\t\"status\":" + "\"%s\"\n" +
            "\t\"error\":" + "\"%s\"\n" +
            "\t\"message\":" + "\"%s\"\n" +
            "\t\"path\":" + "\"%s\"\n" +
            "}", timeStamp, HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase(), message, path);
    response.getWriter().write(jsonResponse);
  }
}
