package com.tianzhu.identity.uaa.mfa.exception;

public class UserMfaConfigDoesNotExistException extends RuntimeException {
    public UserMfaConfigDoesNotExistException(String message) {
        super(message);
    }
}
