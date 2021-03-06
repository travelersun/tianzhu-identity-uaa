package com.tianzhu.identity.uaa.authentication.listener;

import com.tianzhu.identity.uaa.authentication.UaaAuthentication;
import com.tianzhu.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import com.tianzhu.identity.uaa.scim.ScimUser;
import com.tianzhu.identity.uaa.scim.ScimUserProvisioning;
import com.tianzhu.identity.uaa.user.UaaUser;
import com.tianzhu.identity.uaa.user.UaaUserPrototype;
import com.tianzhu.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;

import static org.mockito.Mockito.*;

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
public class UserAuthenticationSuccessListenerTests {

    UserAuthenticationSuccessListener listener;
    ScimUserProvisioning scimUserProvisioning;
    UaaAuthentication mockAuth = mock(UaaAuthentication.class);
    @Before
    public void SetUp()
    {
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        listener = new UserAuthenticationSuccessListener(scimUserProvisioning);
    }

    private UserAuthenticationSuccessEvent getEvent(UaaUserPrototype userPrototype) {
        return new UserAuthenticationSuccessEvent(new UaaUser(userPrototype), mockAuth);
    }

    private ScimUser getScimUser(UaaUser user) {
        ScimUser scimUser = new ScimUser(user.getId(), user.getUsername(), user.getGivenName(), user.getFamilyName());
        scimUser.setVerified(user.isVerified());
        return scimUser;
    }

    @Test
    public void unverifiedUserBecomesVerifiedIfTheyHaveLegacyFlag() {
        String id = "user-id";
        UserAuthenticationSuccessEvent event = getEvent(new UaaUserPrototype()
                .withId(id)
                .withUsername("testUser")
                .withEmail("test@email.com")
                .withVerified(false)
                .withLegacyVerificationBehavior(true));
        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.retrieve(id, zoneId)).thenReturn(getScimUser(event.getUser()));

        listener.onApplicationEvent(event);

        verify(scimUserProvisioning).verifyUser(ArgumentMatchers.eq(id), ArgumentMatchers.eq(-1), ArgumentMatchers.eq(zoneId));
    }

    @Test
    public void unverifiedUserDoesNotBecomeVerifiedIfTheyHaveNoLegacyFlag() {
        String id = "user-id";
        UserAuthenticationSuccessEvent event = getEvent(new UaaUserPrototype()
                .withId(id)
                .withUsername("testUser")
                .withEmail("test@email.com")
                .withVerified(false));
        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.retrieve(id, zoneId)).thenReturn(getScimUser(event.getUser()));

        listener.onApplicationEvent(event);

        verify(scimUserProvisioning, never()).verifyUser(ArgumentMatchers.anyString(), ArgumentMatchers.anyInt(), ArgumentMatchers.eq(zoneId));
    }

    @Test
    public void userLastUpdatedGetsCalledOnEvent() {
        String userId = "userId";
        UserAuthenticationSuccessEvent event = getEvent(new UaaUserPrototype()
        .withId(userId)
        .withEmail("test@test.org")
        .withUsername("testUser")
        .withVerified(false));
        when(scimUserProvisioning.retrieve(userId, IdentityZoneHolder.get().getId())).thenReturn(getScimUser(event.getUser()));

        listener.onApplicationEvent(event);
        verify(scimUserProvisioning, times(1)).updateLastLogonTime(userId, IdentityZoneHolder.get().getId());
    }

    @Test
    public void previousLoginIsSetOnTheAuthentication() {
        String userId = "userId";
        UaaUserPrototype uaaUserPrototype = new UaaUserPrototype()
            .withId(userId)
            .withEmail("test@test.org")
            .withUsername("testUser")
            .withVerified(false)
            .withLastLogonSuccess(123456789L);

        UserAuthenticationSuccessEvent event = new UserAuthenticationSuccessEvent(new UaaUser(uaaUserPrototype), mockAuth);
        when(scimUserProvisioning.retrieve(userId, IdentityZoneHolder.get().getId())).thenReturn(getScimUser(event.getUser()));
        UaaAuthentication authentication = (UaaAuthentication) event.getAuthentication();
        listener.onApplicationEvent(event);
        verify(authentication).setLastLoginSuccessTime(123456789L);
    }

}
