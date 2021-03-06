/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package com.tianzhu.identity.uaa.account;

import com.tianzhu.identity.uaa.account.PasswordConfirmationValidation.PasswordConfirmationException;
import com.tianzhu.identity.uaa.authentication.InvalidCodeException;
import com.tianzhu.identity.uaa.codestore.ExpiringCode;
import com.tianzhu.identity.uaa.codestore.InMemoryExpiringCodeStore;
import com.tianzhu.identity.uaa.error.UaaException;
import com.tianzhu.identity.uaa.scim.ScimUser;
import com.tianzhu.identity.uaa.scim.exception.InvalidPasswordException;
import com.tianzhu.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler;
import com.tianzhu.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletResponse;
import java.sql.Timestamp;

import static junit.framework.TestCase.assertNull;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class ResetPasswordAuthenticationFilterTest {

    private String code;
    private String password;
    private String passwordConfirmation;
    private MockHttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;
    private ResetPasswordService service;
    private ScimUser user;
    private ResetPasswordService.ResetPasswordResponse resetPasswordResponse;
    private ResetPasswordAuthenticationFilter filter;
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    private AuthenticationEntryPoint entryPoint;
    private String email;
    private InMemoryExpiringCodeStore codeStore;

    @Before
    @After
    public void clear() {
        SecurityContextHolder.clearContext();
    }

    @Before
    public void setup() throws Exception {
        codeStore = new InMemoryExpiringCodeStore();
        code = codeStore.generateCode("{}", new Timestamp(System.currentTimeMillis() + 10*60*1000), "", IdentityZoneHolder.get().getId()).getCode();

        password = "test";
        passwordConfirmation = "test";
        email = "test@test.org";

        request = new MockHttpServletRequest("POST", "/reset_password.do");
        request.setParameter("code", code);
        request.setParameter("password", password);
        request.setParameter("password_confirmation", passwordConfirmation);
        request.setParameter("email", email);


        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);

        service = mock(ResetPasswordService.class);
        user = new ScimUser("id", "username", "first name", "last name");
        resetPasswordResponse = new ResetPasswordService.ResetPasswordResponse(user, "/", null);
        when(service.resetPassword(ArgumentMatchers.any(ExpiringCode.class), ArgumentMatchers.eq(password))).thenReturn(resetPasswordResponse);
        authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
        entryPoint = mock(AuthenticationEntryPoint.class);
        filter = new ResetPasswordAuthenticationFilter(service, authenticationSuccessHandler, entryPoint, codeStore);
    }

    @Test
    public void test_happy_day_password_reset() throws Exception {
        happy_day_password_reset(resetPasswordResponse.getRedirectUri());
    }

    @Test
    public void test_happy_day_password_reset_with_redirect() throws Exception {
        reset(service);
        resetPasswordResponse = new ResetPasswordService.ResetPasswordResponse(user, "http://test.com", null);
        when(service.resetPassword(ArgumentMatchers.any(ExpiringCode.class), ArgumentMatchers.eq(password))).thenReturn(resetPasswordResponse);
        happy_day_password_reset(resetPasswordResponse.getRedirectUri());
    }

    @Test
    public void test_happy_day_password_reset_with_null_redirect() throws Exception {
        reset(service);
        resetPasswordResponse = new ResetPasswordService.ResetPasswordResponse(user, null, null);
        when(service.resetPassword(ArgumentMatchers.any(ExpiringCode.class), ArgumentMatchers.eq(password))).thenReturn(resetPasswordResponse);
        happy_day_password_reset(resetPasswordResponse.getRedirectUri());
    }

    @Test
    public void test_happy_day_password_reset_with_home_redirect() throws Exception {
        reset(service);
        resetPasswordResponse = new ResetPasswordService.ResetPasswordResponse(user, "home", null);
        when(service.resetPassword(ArgumentMatchers.any(ExpiringCode.class), ArgumentMatchers.eq(password))).thenReturn(resetPasswordResponse);
        happy_day_password_reset(null);
    }


    public void happy_day_password_reset(String redirectUri) throws Exception {
        filter.doFilterInternal(request, response, chain);
        //do our assertion
        verify(service, times(1)).resetPassword(ArgumentMatchers.any(ExpiringCode.class), ArgumentMatchers.eq(password));
        verify(authenticationSuccessHandler, times(1)).onAuthenticationSuccess(ArgumentMatchers.same(request), ArgumentMatchers.same(response), ArgumentMatchers.any(Authentication.class));
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        verify(chain, times(0)).doFilter(ArgumentMatchers.anyObject(), ArgumentMatchers.anyObject());
        verify(service, times(1)).updateLastLogonTime(ArgumentMatchers.anyString());
        assertEquals(redirectUri, request.getAttribute(UaaSavedRequestAwareAuthenticationSuccessHandler.URI_OVERRIDE_ATTRIBUTE));
    }


    @Test
    public void invalid_password_confirmation() throws Exception {
        request.setParameter("password_confirmation", "invalid");
        Exception e = error_during_password_reset(PasswordConfirmationException.class);
        assertTrue(e instanceof AuthenticationException);
        assertNotNull(e.getCause());
        assertTrue(e.getCause() instanceof PasswordConfirmationException);
        PasswordConfirmationException pe = (PasswordConfirmationException)e.getCause();
        assertEquals("form_error", pe.getMessageCode());
        assertEquals(email, pe.getEmail());
    }


    @Test
    public void error_during_password_reset_uaa_exception() throws Exception {
        reset(service);
        UaaException failed = new UaaException("failed");
        when(service.resetPassword(ArgumentMatchers.any(ExpiringCode.class), ArgumentMatchers.anyString())).thenThrow(failed);
        error_during_password_reset(failed.getClass());
        verify(service, times(1)).resetPassword(ArgumentMatchers.any(ExpiringCode.class), ArgumentMatchers.eq(password));
    }

    @Test
    public void error_during_password_reset_invalid_password_exception() throws Exception {
        reset(service);
        InvalidPasswordException failed = new InvalidPasswordException("failed", HttpStatus.BAD_REQUEST);
        when(service.resetPassword(ArgumentMatchers.any(ExpiringCode.class), ArgumentMatchers.anyString())).thenThrow(failed);
        error_during_password_reset(failed.getClass());
        verify(service, times(1)).resetPassword(ArgumentMatchers.any(ExpiringCode.class), ArgumentMatchers.eq(password));
    }

    @Test
    public void invalid_code_password_reset() throws Exception {
        request.setParameter("code", "invalid");
        error_during_password_reset(InvalidCodeException.class);
    }

    public AuthenticationException error_during_password_reset(Class<? extends Exception> failure) throws Exception {
        ArgumentCaptor<AuthenticationException> authenticationException = ArgumentCaptor.forClass(AuthenticationException.class);
        filter.doFilterInternal(request, response, chain);

        //do our assertion
        verify(authenticationSuccessHandler, times(0)).onAuthenticationSuccess(ArgumentMatchers.same(request), ArgumentMatchers.same(response), ArgumentMatchers.any(Authentication.class));
        verify(entryPoint, times(1)).commence(ArgumentMatchers.same(request), ArgumentMatchers.same(response), authenticationException.capture());
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        AuthenticationException exception = authenticationException.getValue();
        assertSame(failure, exception.getCause().getClass());

        return exception;
    }



}
