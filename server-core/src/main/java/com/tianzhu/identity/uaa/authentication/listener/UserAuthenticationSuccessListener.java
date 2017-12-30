package com.tianzhu.identity.uaa.authentication.listener;

import com.tianzhu.identity.uaa.authentication.UaaAuthentication;
import com.tianzhu.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import com.tianzhu.identity.uaa.scim.ScimUserProvisioning;
import com.tianzhu.identity.uaa.user.UaaUser;
import com.tianzhu.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.ApplicationListener;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public class UserAuthenticationSuccessListener implements ApplicationListener<UserAuthenticationSuccessEvent> {

    private final ScimUserProvisioning scimUserProvisioning;

    public UserAuthenticationSuccessListener(ScimUserProvisioning scimUserProvisioning) {
        this.scimUserProvisioning = scimUserProvisioning;
    }

    @Override
    public void onApplicationEvent(UserAuthenticationSuccessEvent event) {
        UaaUser user = event.getUser();
        if(user.isLegacyVerificationBehavior() && !user.isVerified()) {
            scimUserProvisioning.verifyUser(user.getId(), -1, IdentityZoneHolder.get().getId());
        }
        UaaAuthentication authentication = (UaaAuthentication) event.getAuthentication();
        authentication.setLastLoginSuccessTime(user.getLastLogonTime());
        scimUserProvisioning.updateLastLogonTime(user.getId(), IdentityZoneHolder.get().getId());
    }
}
