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

import junit.framework.TestCase;
import org.junit.Before;
import org.mockito.ArgumentMatchers;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;

import static org.mockito.Mockito.*;

public class ChainedAuthenticationManagerTest extends TestCase {

    private Authentication success;
    private Authentication failure;
    private AuthenticationManager authenticateTrue;
    private AuthenticationManager authenticateFalse;
    private AuthenticationManager authenticateNull;
    private AuthenticationManager authenticateThrow;
    private ChainedAuthenticationManager.AuthenticationManagerConfiguration[] managers;
    private ChainedAuthenticationManager authMgr = new ChainedAuthenticationManager();
    private AuthenticationManager loginAuthenticationManager;

    @Before
    public void setUp() throws Exception {
        success = mock(Authentication.class);
        failure = mock(Authentication.class);

        authenticateTrue = mock(AuthenticationManager.class);
        authenticateFalse = mock(AuthenticationManager.class);
        authenticateNull = mock(AuthenticationManager.class);
        authenticateThrow = mock(AuthenticationManager.class);
        loginAuthenticationManager = mock(AuthenticationManager.class);

        when(success.isAuthenticated()).thenReturn(true);
        when(failure.isAuthenticated()).thenReturn(false);
        when(authenticateTrue.authenticate(ArgumentMatchers.any(Authentication.class))).thenReturn(success);
        when(loginAuthenticationManager.authenticate(ArgumentMatchers.any(Authentication.class))).thenReturn(success);
        when(authenticateFalse.authenticate(ArgumentMatchers.any(Authentication.class))).thenReturn(failure);
        when(authenticateNull.authenticate(ArgumentMatchers.any(Authentication.class))).thenReturn(null);
        when(authenticateThrow.authenticate(ArgumentMatchers.any(Authentication.class))).thenThrow(new BadCredentialsException("mock throw"));

        managers = new ChainedAuthenticationManager.AuthenticationManagerConfiguration[3];
        managers[0] = new ChainedAuthenticationManager.AuthenticationManagerConfiguration(null,null);
        managers[1] = new ChainedAuthenticationManager.AuthenticationManagerConfiguration(null,ChainedAuthenticationManager.IF_PREVIOUS_FALSE);
        managers[2] = new ChainedAuthenticationManager.AuthenticationManagerConfiguration(loginAuthenticationManager,ChainedAuthenticationManager.IF_PREVIOUS_TRUE);
        authMgr.setDelegates(managers);
    }

    public void testUaaAuthTrue() throws Exception {
        managers[0].setAuthenticationManager(authenticateTrue);
        managers[1].setAuthenticationManager(authenticateFalse);
        Authentication result = authMgr.authenticate(failure);
        assertNotNull(result);
        assertTrue(result.isAuthenticated());
        verify(authenticateTrue, times(1)).authenticate(ArgumentMatchers.any(Authentication.class));
        verify(authenticateFalse, times(0)).authenticate(ArgumentMatchers.any(Authentication.class));
        verify(loginAuthenticationManager, times(0)).authenticate(ArgumentMatchers.any(Authentication.class));
    }

    public void testUaaAuthFalseLdapTrue() throws Exception {
        managers[0].setAuthenticationManager(authenticateFalse);
        managers[1].setAuthenticationManager(authenticateTrue);
        Authentication result = authMgr.authenticate(failure);
        assertNotNull(result);
        assertTrue(result.isAuthenticated());
        verify(authenticateTrue, times(1)).authenticate(ArgumentMatchers.any(Authentication.class));
        verify(authenticateFalse, times(1)).authenticate(ArgumentMatchers.any(Authentication.class));
        verify(loginAuthenticationManager, times(1)).authenticate(ArgumentMatchers.any(Authentication.class));
    }

    public void testUaaAuthFalseLdapFalse() throws Exception {
        managers[0].setAuthenticationManager(authenticateFalse);
        managers[1].setAuthenticationManager(authenticateFalse);
        Authentication result = authMgr.authenticate(failure);
        assertNull(result);
        verify(authenticateFalse, times(2)).authenticate(ArgumentMatchers.any(Authentication.class));
        verify(loginAuthenticationManager, times(0)).authenticate(ArgumentMatchers.any(Authentication.class));
    }

    public void testUaaAuthThrowLdapAuthFalse() throws Exception {
        managers[0].setAuthenticationManager(authenticateThrow);
        managers[1].setAuthenticationManager(authenticateFalse);
        try {
            Authentication result = authMgr.authenticate(failure);
            fail("Should have thrown exception");
        }catch (BadCredentialsException x) {
        }

        verify(authenticateThrow, times(1)).authenticate(ArgumentMatchers.any(Authentication.class));
        verify(authenticateFalse, times(1)).authenticate(ArgumentMatchers.any(Authentication.class));
        verify(loginAuthenticationManager, times(0)).authenticate(ArgumentMatchers.any(Authentication.class));
    }

    public void testUaaAuthThrowLdapAuthTrue() throws Exception {
        managers[0].setAuthenticationManager(authenticateThrow);
        managers[1].setAuthenticationManager(authenticateTrue);
        Authentication result = authMgr.authenticate(failure);
        assertNotNull(result);
        assertTrue(result.isAuthenticated());
        verify(authenticateThrow, times(1)).authenticate(ArgumentMatchers.any(Authentication.class));
        verify(authenticateTrue, times(1)).authenticate(ArgumentMatchers.any(Authentication.class));
        verify(loginAuthenticationManager, times(1)).authenticate(ArgumentMatchers.any(Authentication.class));
    }
}
