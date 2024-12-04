package com.backend.exceptions;

import lombok.NoArgsConstructor;

import java.util.Map;

@NoArgsConstructor
public class ResourceAlreadyExistedException extends AbstractException{
  public ResourceAlreadyExistedException(String message, Map<String, String> details) {
    super(message, details);
  }
}

