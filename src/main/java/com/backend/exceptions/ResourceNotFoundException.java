package com.backend.exceptions;

import lombok.NoArgsConstructor;

import java.util.Map;

@NoArgsConstructor
public class ResourceNotFoundException extends AbstractException{
  public ResourceNotFoundException(String message, Map<String, String> details) {
    super(message, details);
  }
}
