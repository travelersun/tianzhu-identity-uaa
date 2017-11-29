package com.tianzhu.identity.uaa.account;

import com.tianzhu.identity.uaa.codestore.ExpiringCode;

public class ForgotPasswordInfo {
    private String userId;
    private ExpiringCode resetPasswordCode;
    private String email;

    public ForgotPasswordInfo(String userId, String email, ExpiringCode resetPasswordCode) {
        this.userId = userId;
        this.resetPasswordCode = resetPasswordCode;
        this.email = email;
    }

    public String getUserId() {
        return userId;
    }

    public ExpiringCode getResetPasswordCode() {
        return resetPasswordCode;
    }
 
    public String getEmail() {
        return email;
    }
}
