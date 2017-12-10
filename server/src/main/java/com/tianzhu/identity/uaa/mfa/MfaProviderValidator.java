package com.tianzhu.identity.uaa.mfa;

public interface MfaProviderValidator {
    void validate(MfaProvider mfaProvider);
}
