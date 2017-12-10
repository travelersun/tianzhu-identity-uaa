package com.tianzhu.identity.uaa.mfa.exception;

public class UserMfaConfigAlreadyExistsException extends RuntimeException {
    public UserMfaConfigAlreadyExistsException(String message) {
        super(message);
    }
}
