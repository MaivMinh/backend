package com.backend.exceptions;

import org.springframework.core.NestedRuntimeException;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(annotations = RestController.class)
@Order(1)
public class GlobalExceptionsHandling {


  @ExceptionHandler({BadCredentialsException.class})
  public ResponseEntity<ExceptionResponse> handleBadCredentialsExceptions(BadCredentialsException exception) {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(new ExceptionResponse(exception.getMessage(), null));
  }

  @ExceptionHandler({ResourceNotFoundException.class})
  public ResponseEntity<ExceptionResponse> handleResourceNotFoundExceptions(ResourceNotFoundException exception) {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(new ExceptionResponse(exception.getMessage(), exception.getDetails()));
  }

  @ExceptionHandler({AbstractException.class})
  public ResponseEntity<ExceptionResponse> handleAbstractionExceptions(AbstractException exception) {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(new ExceptionResponse(exception.getMessage(), exception.getDetails()));
  }

  @ExceptionHandler({MethodArgumentNotValidException.class})
  public ResponseEntity<ExceptionResponse> handleMethodArgumentNotValidException() {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ExceptionResponse("Method arguments not valid!", null));
  }

  @ExceptionHandler({NestedRuntimeException.class})
  public ResponseEntity<ExceptionResponse> handleNestedRuntimeException(NestedRuntimeException exception) {
    return  ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ExceptionResponse("Invalid params", null));
  }


  @ExceptionHandler({RuntimeException.class})
  public ResponseEntity<ExceptionResponse> handleRuntimeException(RuntimeException exception) {
    exception.printStackTrace();
    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(new ExceptionResponse(exception.getMessage(), null));
  }
}
