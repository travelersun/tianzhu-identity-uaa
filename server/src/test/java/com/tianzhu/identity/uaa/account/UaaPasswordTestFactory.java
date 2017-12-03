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
package com.tianzhu.identity.uaa.account;

import com.tianzhu.identity.uaa.authentication.UaaAuthentication;
import com.tianzhu.identity.uaa.authentication.UaaPrincipal;
import com.tianzhu.identity.uaa.user.UaaAuthority;
import com.tianzhu.identity.uaa.user.UaaUser;

/**
 * @author Dave Syer
 * 
 */
public class UaaPasswordTestFactory {

    public static UaaPrincipal getPrincipal(String id, String name, String email) {
        return new UaaPrincipal(new UaaUser(id, name, email, name, "familyName"));
    }

    public static UaaAuthentication getAuthentication(String id, String name, String email) {
        return new UaaAuthentication(getPrincipal(id, name, email), UaaAuthority.USER_AUTHORITIES, null);
    }

}
