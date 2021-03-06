package com.tianzhu.identity.uaa.mfa;

import com.tianzhu.identity.uaa.mfa.exception.InvalidMfaProviderConfigException;

public class GoogleMfaProviderConfigValidator implements MfaProviderConfigValidator<GoogleMfaProviderConfig> {

    @Override
    public void validate(GoogleMfaProviderConfig mfaProviderConfig) throws InvalidMfaProviderConfigException {
        if(mfaProviderConfig.getAlgorithm() == null) {
            throw new InvalidMfaProviderConfigException("Algorithm must be one of " + GoogleMfaProviderConfig.Algorithm.getStringValues());
        }
        if(mfaProviderConfig.getDigits() < 1) {
            throw new InvalidMfaProviderConfigException("Digits must be greater than 0");
        }
        if(mfaProviderConfig.getDuration() < 1) {
            throw new InvalidMfaProviderConfigException("Duration must be greater than 0");
        }
    }
}
