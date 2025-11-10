package com.lanny.spring_security_template.domain.exception;

public class UserDeletedException extends RuntimeException {
  public UserDeletedException(String message) {
    super(message);
  }
}
