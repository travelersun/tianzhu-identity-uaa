/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package com.tianzhu.identity.uaa.account.event;

import com.tianzhu.identity.uaa.audit.event.AbstractUaaEvent;
import com.tianzhu.identity.uaa.scim.ScimUser;
import com.tianzhu.identity.uaa.scim.ScimUser.Email;
import com.tianzhu.identity.uaa.scim.ScimUserProvisioning;
import com.tianzhu.identity.uaa.scim.exception.ScimResourceNotFoundException;
import com.tianzhu.identity.uaa.user.UaaUser;
import com.tianzhu.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Date;
import java.util.List;

import static java.util.Optional.ofNullable;
import static com.tianzhu.identity.uaa.authentication.SystemAuthentication.SYSTEM_AUTHENTICATION;

/**
 * Event publisher for password changes with the resulting event type varying
 * according to the input and outcome. Can be
 * used as an aspect intercepting calls to a component that changes user
 * password.
 *
 */
public class PasswordChangeEventPublisher implements ApplicationEventPublisherAware {

    private ScimUserProvisioning dao;

    private ApplicationEventPublisher publisher;

    public PasswordChangeEventPublisher(ScimUserProvisioning provisioning) {
        this.dao = provisioning;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    public void passwordFailure(String userId, Exception e) {
        UaaUser user = getUser(userId);
        publish(new PasswordChangeFailureEvent(e.getMessage(), user, getPrincipal()));
    }

    public void passwordChange(String userId) {
        publish(new PasswordChangeEvent("Password changed", getUser(userId), getPrincipal()));
    }

    private UaaUser getUser(String userId) {
        try {
            // If the request came in for a user by id we should be able to
            // retrieve the username
            ScimUser scimUser = dao.retrieve(userId, IdentityZoneHolder.get().getId());
            Date today = new Date();
            if (scimUser != null) {
                return new UaaUser(
                    scimUser.getId(),
                    scimUser.getUserName(),
                    "N/A",
                    getEmail(scimUser),
                    null,
                    scimUser.getGivenName(),
                    scimUser.getFamilyName(),
                    today,
                    today,
                    scimUser.getOrigin(),
                    scimUser.getExternalId(),
                    scimUser.isVerified(),
                    scimUser.getZoneId(),
                    scimUser.getSalt(),
                    scimUser.getPasswordLastModified());
            }
        } catch (ScimResourceNotFoundException e) {
            // ignore
        }
        return null;
    }

    private String getEmail(ScimUser scimUser) {
        List<Email> emails = scimUser.getEmails();
        if (emails == null || emails.isEmpty()) {
            return scimUser.getUserName().contains("@") ? scimUser.getUserName() : scimUser.getUserName()
                            + "@unknown.org";
        }
        for (Email email : emails) {
            if (email.isPrimary()) {
                return email.getValue();
            }
        }
        return scimUser.getEmails().get(0).getValue();
    }

    protected Authentication getPrincipal() {
        return ofNullable(SecurityContextHolder.getContext().getAuthentication())
            .orElse(SYSTEM_AUTHENTICATION);
    }

    private void publish(AbstractUaaEvent event) {
        if (publisher != null) {
            publisher.publishEvent(event);
        }
    }

}
