/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package com.tianzhu.identity.uaa.mock.password;


import com.tianzhu.identity.uaa.mock.InjectedMockContextTest;
import com.tianzhu.identity.uaa.mock.util.MockMvcUtils;
import com.tianzhu.identity.uaa.test.SnippetUtils;
import com.tianzhu.identity.uaa.scim.ScimUser;
import com.tianzhu.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.Before;
import org.junit.Test;
import org.springframework.restdocs.headers.HeaderDocumentation;
import org.springframework.restdocs.request.RequestDocumentation;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

public class PasswordEndpointsDocs extends InjectedMockContextTest {

    private String loginToken;
    private String clientId;
    private ScimUser user;

    @Before
    public void setup_for_password_reset() throws Exception {
        clientId = "login";
        loginToken = MockMvcUtils.getClientOAuthAccessToken(getMockMvc(), clientId, "loginsecret", "oauth.login");
        String adminToken = MockMvcUtils.getClientOAuthAccessToken(getMockMvc(), "admin", "adminsecret", null);
        String userName = "user-"+new RandomValueStringGenerator().generate().toLowerCase()+"@test.org";
        user = new ScimUser(null, userName, "given", "last");
        user.setPassword("password");
        user.setPrimaryEmail(user.getUserName());
        user = MockMvcUtils.createUser(getMockMvc(), adminToken, user);
    }

    @Test
    public void document_password_reset() throws Exception {

        Snippet responseFields = responseFields(
            fieldWithPath("code").type(STRING).description("The code to used to invoke the `/password_change` endpoint with or to initiate the `/reset_password` flow."),
            fieldWithPath("user_id").type(STRING).description("The UUID identifying the user.")
        );

        Snippet requestParameters = RequestDocumentation.requestParameters(
            SnippetUtils.parameterWithName("client_id").optional(null).type(STRING).description("Optional client_id "),
            SnippetUtils.parameterWithName("redirect_uri").optional(null).type(STRING).description("Optional redirect_uri to be used if the `/reset_password` flow is completed.")
        );

        Snippet requestHeaders = HeaderDocumentation.requestHeaders(
            SnippetUtils.headerWithName("Authorization").required().description("Bearer token with the scope `oauth.login` present."),
            SnippetUtils.headerWithName(IdentityZoneSwitchingFilter.HEADER).optional(null).description("If using a `zones.<zoneId>.admin scope/token, indicates what zone this request goes to by supplying a zone_id."),
            SnippetUtils.headerWithName(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER).optional(null).description("If using a `zones.<zoneId>.admin scope/token, indicates what zone this request goes to by supplying a subdomain.")
        );


        MockHttpServletRequestBuilder post = post("/password_resets")
            .header("Authorization", "Bearer " + loginToken)
            .contentType(APPLICATION_JSON)
            .param("client_id", clientId)
            .param("redirect_uri", "http://go.to.my.app/after/reset")
            .content(user.getUserName())
            .accept(APPLICATION_JSON);

        getMockMvc().perform(post)
            .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, requestParameters, responseFields));

    }

}
