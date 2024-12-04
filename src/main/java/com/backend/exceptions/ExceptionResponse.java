package com.backend.exceptions;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.Map;

@Getter
@Setter
@AllArgsConstructor
public class ExceptionResponse implements Serializable {
  private String message;
  private Map<String, String> details;
}
