package com.tianzhu.identity.uaa.mfa;

import com.tianzhu.identity.uaa.mfa.exception.InvalidMfaProviderConfigException;

public interface MfaProviderConfigValidator<T extends AbstractMfaProviderConfig>{
    void validate(T mfaProviderConfig) throws InvalidMfaProviderConfigException;
}
