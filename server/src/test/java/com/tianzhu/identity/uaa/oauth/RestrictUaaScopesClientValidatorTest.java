/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package com.tianzhu.identity.uaa.oauth;

import com.tianzhu.identity.uaa.client.ClientDetailsValidator;
import com.tianzhu.identity.uaa.client.InvalidClientDetailsException;
import com.tianzhu.identity.uaa.client.RestrictUaaScopesClientValidator;
import com.tianzhu.identity.uaa.client.UaaScopes;
import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import static com.tianzhu.identity.uaa.client.ClientDetailsValidator.Mode.*;
import static org.junit.Assert.fail;


public class RestrictUaaScopesClientValidatorTest {

    List<String> goodScopes = Arrays.asList("openid","uaa.resource","uaa.none");
    List<String> badScopes = new UaaScopes().getUaaScopes();
    RestrictUaaScopesClientValidator validator = new RestrictUaaScopesClientValidator(new UaaScopes());

    @Test
    public void testValidate() throws Exception {
        List<ClientDetailsValidator.Mode> restrictModes = Arrays.asList(CREATE, MODIFY);
        List<ClientDetailsValidator.Mode> nonRestrictModes = Arrays.asList(DELETE);
        BaseClientDetails client = new BaseClientDetails("clientId","","","client_credentials,password","");

        for (String s : badScopes) {
            client.setScope(Collections.singletonList(s));
            validateClient(restrictModes, nonRestrictModes, client, s);
            client.setScope(Collections.EMPTY_LIST);
            client.setAuthorities(Collections.singletonList(new SimpleGrantedAuthority(s)));
            validateClient(restrictModes, nonRestrictModes, client, s);
            client.setAuthorities(Collections.EMPTY_LIST);
        }

        for (String s : goodScopes) {
            List<ClientDetailsValidator.Mode> goodmodes = new LinkedList<>(restrictModes);
            goodmodes.addAll(nonRestrictModes);
            client.setScope(Collections.singletonList(s));
            validateClient(Collections.EMPTY_LIST, goodmodes, client, s);
            client.setScope(Collections.EMPTY_LIST);
            client.setAuthorities(Collections.singletonList(new SimpleGrantedAuthority(s)));
            validateClient(Collections.EMPTY_LIST, goodmodes, client, s);
            client.setAuthorities(Collections.EMPTY_LIST);
        }

    }

    protected void validateClient(List<ClientDetailsValidator.Mode> restrictModes, List<ClientDetailsValidator.Mode> nonRestrictModes, BaseClientDetails client, String s) {
        for (ClientDetailsValidator.Mode m : restrictModes) {
            try {
                validator.validate(client, m);
                fail("Scope:"+s+" should not be valid during "+m+" mode.");
            } catch (InvalidClientDetailsException x) {
                //expected
            }
        }
        for (ClientDetailsValidator.Mode m : nonRestrictModes) {
            try {
                validator.validate(client, m);
            } catch (InvalidClientDetailsException x) {
                fail("Scope:"+s+" should be valid during "+m+" mode.");
            }
        }
    }


}