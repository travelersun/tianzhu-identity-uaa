/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package com.tianzhu.identity.uaa.login;

import com.tianzhu.identity.uaa.authentication.PasswordChangeRequiredException;
import com.tianzhu.identity.uaa.authentication.UaaAuthentication;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import java.io.IOException;

import static com.tianzhu.identity.uaa.login.ForcePasswordChangeController.FORCE_PASSWORD_EXPIRED_USER;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.mockito.internal.verification.VerificationModeFactory.times;

public class UaaAuthenticationFailureHandlerTests {

    private AuthenticationFailureHandler failureHandler;
    private MockHttpServletResponse response;
    private MockHttpServletRequest request;
    private UaaAuthenticationFailureHandler uaaAuthenticationFailureHandler;

    @Before
    public void setup() throws Exception {
        failureHandler = mock(AuthenticationFailureHandler.class);
        uaaAuthenticationFailureHandler = new UaaAuthenticationFailureHandler(failureHandler);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    public void onAuthenticationFailure() throws Exception {
        AuthenticationException exception = mock(AuthenticationException.class);
        uaaAuthenticationFailureHandler.onAuthenticationFailure(request, response, exception);
        verify(failureHandler, times(1)).onAuthenticationFailure(ArgumentMatchers.same(request), ArgumentMatchers.same(response), ArgumentMatchers.same(exception));
        validateCookie();
    }

    @Test
    public void onAuthenticationFailure_Without_Delegate() throws Exception {
        AuthenticationException exception = mock(AuthenticationException.class);
        uaaAuthenticationFailureHandler = new UaaAuthenticationFailureHandler(null);
        uaaAuthenticationFailureHandler.onAuthenticationFailure(request, response, exception);
        validateCookie();
    }

    @Test
    public void logout() throws Exception {
        uaaAuthenticationFailureHandler.logout(request, response, mock(Authentication.class));
        validateCookie();
    }

    @Test
    public void onAuthenticationFailure_ForcePasswordChange() throws IOException, ServletException {
        PasswordChangeRequiredException exception = mock(PasswordChangeRequiredException.class);
        UaaAuthentication uaaAuthentication = mock(UaaAuthentication.class);
        when(exception.getAuthentication()).thenReturn(uaaAuthentication);
        uaaAuthenticationFailureHandler.onAuthenticationFailure(request, response, exception);
        assertNotNull(request.getSession().getAttribute(FORCE_PASSWORD_EXPIRED_USER));
        assertEquals(uaaAuthentication, request.getSession().getAttribute(FORCE_PASSWORD_EXPIRED_USER));
        validateCookie();
        assertEquals("/force_password_change", response.getRedirectedUrl());
    }

    private void validateCookie() {
        Cookie cookie = response.getCookie("Current-User");
        assertNotNull(cookie);
        assertEquals(0, cookie.getMaxAge());
        assertFalse(cookie.isHttpOnly());
    }

}