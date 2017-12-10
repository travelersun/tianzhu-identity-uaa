/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */
package com.tianzhu.identity.uaa.authentication.manager;


import com.tianzhu.identity.uaa.constants.OriginKeys;
import com.tianzhu.identity.uaa.provider.IdentityProvider;
import com.tianzhu.identity.uaa.provider.IdentityProviderProvisioning;
import com.tianzhu.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import com.tianzhu.identity.uaa.test.JdbcTestBase;
import com.tianzhu.identity.uaa.user.MockUaaUserDatabase;
import com.tianzhu.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CheckIdpEnabledAuthenticationManagerTest extends JdbcTestBase {

    private IdentityProviderProvisioning identityProviderProvisioning;
    private CheckIdpEnabledAuthenticationManager manager;
    private UsernamePasswordAuthenticationToken token;

    @Before
    public void setupAuthManager() throws Exception {
        identityProviderProvisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        MockUaaUserDatabase userDatabase = new MockUaaUserDatabase(u -> u.withId("id").withUsername("marissa").withEmail("test@test.org").withVerified(true).withPassword("koala"));
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        when(encoder.matches(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())).thenReturn(true);
        AuthzAuthenticationManager authzAuthenticationManager = new AuthzAuthenticationManager(userDatabase, encoder, identityProviderProvisioning);
        authzAuthenticationManager.setOrigin(OriginKeys.UAA);
        manager = new CheckIdpEnabledAuthenticationManager(authzAuthenticationManager, OriginKeys.UAA, identityProviderProvisioning);
        token = new UsernamePasswordAuthenticationToken("marissa", "koala");
    }


    @Test
    public void testAuthenticate() throws Exception {
        Authentication auth = manager.authenticate(token);
        assertNotNull(auth);
        assertTrue(auth.isAuthenticated());
    }

    @Test(expected = ProviderNotFoundException.class)
    public void testAuthenticateIdpDisabled() throws Exception {
        IdentityProvider provider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        provider.setActive(false);
        identityProviderProvisioning.update(provider, IdentityZoneHolder.get().getId());
        manager.authenticate(token);
    }

}
