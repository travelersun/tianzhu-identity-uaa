/*******************************************************************************
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
 *******************************************************************************/
package com.tianzhu.identity.uaa.audit.event;

import com.tianzhu.identity.uaa.audit.AuditEvent;
import com.tianzhu.identity.uaa.audit.UaaAuditService;
import com.tianzhu.identity.uaa.authentication.AuthzAuthenticationRequest;
import com.tianzhu.identity.uaa.authentication.UaaAuthenticationDetails;
import com.tianzhu.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import com.tianzhu.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import com.tianzhu.identity.uaa.authentication.event.UserNotFoundEvent;
import com.tianzhu.identity.uaa.user.UaaUser;
import com.tianzhu.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Luke Taylor
 */
public class AuditListenerTests {

    private AuditListener listener;
    private UaaAuditService auditor;
    private UaaUser user = new UaaUser("auser", "password", "auser@blah.com", "A", "User");
    private UaaAuthenticationDetails details;

    @Before
    public void setUp() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        details = new UaaAuthenticationDetails(request);
        auditor = mock(UaaAuditService.class);
        listener = new AuditListener(auditor);
    }

    @Test
    public void userNotFoundIsAudited() throws Exception {
        AuthzAuthenticationRequest req = new AuthzAuthenticationRequest("breakin", "password", details);
        listener.onApplicationEvent(new UserNotFoundEvent(req));
        verify(auditor).log(ArgumentMatchers.isA(AuditEvent.class), eq(IdentityZoneHolder.get().getId()));
    }

    @Test
    public void successfulUserAuthenticationIsAudited() throws Exception {
        listener.onApplicationEvent(new UserAuthenticationSuccessEvent(user, mock(Authentication.class)));
        verify(auditor).log(ArgumentMatchers.isA(AuditEvent.class), eq(IdentityZoneHolder.get().getId()));
    }

    @Test
    public void failedUserAuthenticationIsAudited() throws Exception {
        AuthzAuthenticationRequest req = new AuthzAuthenticationRequest("auser", "password", details);
        listener.onApplicationEvent(new UserAuthenticationFailureEvent(user, req));
        verify(auditor).log(ArgumentMatchers.isA(AuditEvent.class), eq(IdentityZoneHolder.get().getId()));
    }

}
