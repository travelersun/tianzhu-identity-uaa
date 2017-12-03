package com.tianzhu.identity.uaa.account;

import java.util.Map;

public interface ChangeEmailService {

    void beginEmailChange(String userId, String userEmail, String newEmail, String clientId, String redirectUri);

    Map<String, String> completeVerification(String code);

}
