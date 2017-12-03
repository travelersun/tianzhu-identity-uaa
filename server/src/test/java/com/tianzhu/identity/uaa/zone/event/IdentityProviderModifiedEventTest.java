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

package com.tianzhu.identity.uaa.zone.event;

import com.tianzhu.identity.uaa.constants.OriginKeys;
import com.tianzhu.identity.uaa.provider.IdentityProvider;
import com.tianzhu.identity.uaa.provider.SamlIdentityProviderDefinition;
import com.tianzhu.identity.uaa.provider.saml.BootstrapSamlIdentityProviderConfiguratorTests;
import com.tianzhu.identity.uaa.zone.IdentityZone;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.*;

import static org.junit.Assert.assertEquals;


public class IdentityProviderModifiedEventTest {

    private IdentityProvider<SamlIdentityProviderDefinition> provider;

    @Before
    public void setup() {
        String origin = "idp-mock-saml-"+new RandomValueStringGenerator().generate();
        String metadata = String.format(BootstrapSamlIdentityProviderConfiguratorTests.xmlWithoutID, "http://localhost:9999/metadata/"+origin);
        provider = new IdentityProvider<>();
        provider.setId("id");
        provider.setActive(true);
        provider.setName(origin);
        provider.setIdentityZoneId(IdentityZone.getUaa().getId());
        provider.setType(OriginKeys.SAML);
        provider.setIdentityZoneId(IdentityZone.getUaa().getId());
        provider.setOriginKey(origin);
        SamlIdentityProviderDefinition samlDefinition =
            new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setLinkText("Test SAML Provider");
        samlDefinition.setEmailDomain(Arrays.asList("test.com", "test2.com"));
        List<String> externalGroupsWhitelist = new ArrayList<>();
        externalGroupsWhitelist.add("value");
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "first_name");
        samlDefinition.setExternalGroupsWhitelist(externalGroupsWhitelist);
        samlDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(samlDefinition);
    }

    @Test
    public void identityProviderCreated() throws Exception {
        evaluateEventString(IdentityProviderModifiedEvent.identityProviderCreated(provider));
    }

    @Test
    public void identityProviderModified() throws Exception {
        evaluateEventString(IdentityProviderModifiedEvent.identityProviderModified(provider));
    }

    public void evaluateEventString(IdentityProviderModifiedEvent event) {
        String s = event.getAuditEvent().getData();
        assertEquals(
            String.format(IdentityProviderModifiedEvent.dataFormat,
                          provider.getId(),
                          provider.getType(),
                          provider.getOriginKey(),
                          provider.getIdentityZoneId()),
            s);
    }

}