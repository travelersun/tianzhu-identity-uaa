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
package com.tianzhu.identity.uaa.account.event;

import com.tianzhu.identity.uaa.audit.event.AbstractUaaEvent;
import com.tianzhu.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;

import java.security.Principal;

/**
 * @author Dave Syer
 */
abstract class AbstractPasswordChangeEvent extends AbstractUaaEvent {

    private UaaUser user;

    private String message;

    public AbstractPasswordChangeEvent(String message, UaaUser user, Authentication authentication) {
        super(authentication);
        this.message = message;
        this.user = user;
    }

    public UaaUser getUser() {
        return user;
    }

    public Principal getPrincipal() {
        return getAuthentication();
    }

    public String getMessage() {
        return message;
    }

}
