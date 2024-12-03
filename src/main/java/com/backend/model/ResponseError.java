package com.backend.model;

import com.backend.response.ResponseData;

public class ResponseError extends ResponseData {
  private int status;
  private String message;

  public ResponseError(int value, String message) {
    super(value, message);
  }
}
