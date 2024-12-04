package com.backend.exceptions;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ExceptionMessage {

  BAD_REQUEST("BAD REQUEST"),

  RESOURCE_NOT_FOUND("RESOURCE NOT FOUND"),

  RESOURCE_ALREADY_EXISTS("RESOURCE_ALREADY_EXISTS");
  private final String description;
}