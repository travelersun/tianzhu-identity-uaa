/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package com.tianzhu.identity.client.integration;

import com.tianzhu.identity.client.UaaContext;
import com.tianzhu.identity.client.UaaContextFactory;
import com.tianzhu.identity.client.token.GrantType;
import com.tianzhu.identity.client.token.TokenRequest;
import com.tianzhu.identity.uaa.zone.IdentityZone;
import com.tianzhu.identity.uaa.zone.IdentityZoneConfiguration;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.net.URI;

import static com.tianzhu.identity.client.integration.ClientIntegrationTestUtilities.GENERATOR;
import static com.tianzhu.identity.client.integration.ClientIntegrationTestUtilities.UAA_URI;
import static org.springframework.http.HttpMethod.POST;

public class IdentityZoneConfigurationIntegrationTest {

    private UaaContextFactory factory;

    @Rule
    public IsUAAListeningRule uaaListeningRule = new IsUAAListeningRule(UAA_URI, false);

    @Before
    public void setUp() throws Exception {
        factory =
            UaaContextFactory.factory(new URI(UAA_URI))
                .authorizePath("/oauth/authorize")
                .tokenPath("/oauth/token");
    }

    @Test
    public void create_zone_without_client_api() throws Exception {
        TokenRequest clientCredentials = factory.tokenRequest()
            .setClientId("identity")
            .setClientSecret("identitysecret")
            .setGrantType(GrantType.CLIENT_CREDENTIALS);

        UaaContext context = factory.authenticate(clientCredentials);

        String zoneId = GENERATOR.generate();
        IdentityZone zone = new IdentityZone()
            .setId(zoneId)
            .setName(zoneId)
            .setSubdomain(zoneId)
            .setConfig(new IdentityZoneConfiguration());

        ResponseEntity<IdentityZone> created = context.getRestTemplate().exchange(
            UAA_URI+"/identity-zones",
            POST,
            new HttpEntity<>(zone),
            IdentityZone.class
        );

        Assert.assertEquals(HttpStatus.CREATED, created.getStatusCode());

    }
}
