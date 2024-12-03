package com.backend.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ResponseData {
  private int status;
  private String message;
  @JsonInclude(JsonInclude.Include.NON_NULL)  // Khi data = null thì sẽ không có trong Response.
  private Object data;

  public ResponseData(int status, String message) {
    this.status = status;
    this.message = message;
    data = null;
  }
}

