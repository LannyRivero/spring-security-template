package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a user account has been logically deleted (soft delete)
 * and is no longer allowed to authenticate.
 */
public class UserDeletedException extends RuntimeException {

  public UserDeletedException() {
    super("User account has been deleted");
  }

  public UserDeletedException(String message) {
    super(message);
  }
}
