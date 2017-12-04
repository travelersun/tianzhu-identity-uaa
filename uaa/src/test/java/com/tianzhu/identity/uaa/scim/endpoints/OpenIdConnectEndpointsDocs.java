package com.tianzhu.identity.uaa.scim.endpoints;

import com.tianzhu.identity.uaa.mock.InjectedMockContextTest;
import com.tianzhu.identity.uaa.test.SnippetUtils;
import org.junit.Test;
import org.springframework.restdocs.payload.PayloadDocumentation;
import org.springframework.restdocs.snippet.Snippet;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by miles on 9/23/16.
 */
public class OpenIdConnectEndpointsDocs extends InjectedMockContextTest {

    @Test
    public void getWellKnownOpenidConf() throws Exception {

        Snippet responseFields = PayloadDocumentation.responseFields(
            SnippetUtils.fieldWithPath("issuer").description("URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier."),
            SnippetUtils.fieldWithPath("authorization_endpoint").description("URL of authorization endpoint."),
            SnippetUtils.fieldWithPath("token_endpoint").description("URL of token endpoint."),
            SnippetUtils.fieldWithPath("userinfo_endpoint").description("URL of the OP's UserInfo Endpoint."),
            SnippetUtils.fieldWithPath("jwks_uri").description("URL of the OP's JSON Web Key Set document."),
            SnippetUtils.fieldWithPath("scopes_supported").description("JSON array containing a list of the OAuth 2.0 scope values that this server supports."),
            SnippetUtils.fieldWithPath("subject_types_supported").description("JSON array containing a list of the Subject Identifier types that this OP supports."),
            SnippetUtils.fieldWithPath("token_endpoint_auth_methods_supported").description("JSON array containing a list of Client Authentication methods supported by this Token Endpoint."),
            SnippetUtils.fieldWithPath("token_endpoint_auth_signing_alg_values_supported").description("JSON array containing a list of the JWS signing algorithms."),
            SnippetUtils.fieldWithPath("response_types_supported").description("JSON array containing a list of the OAuth 2.0 response_type values that this OP supports."),
            SnippetUtils.fieldWithPath("id_token_signing_alg_values_supported").description("JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT."),
            SnippetUtils.fieldWithPath("id_token_encryption_alg_values_supported").description("JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP."),
            SnippetUtils.fieldWithPath("claim_types_supported").description("JSON array containing a list of the Claim Types that the OpenID Provider supports."),
            SnippetUtils.fieldWithPath("claims_supported").description("JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for."),
            SnippetUtils.fieldWithPath("claims_parameter_supported").description("Boolean value specifying whether the OP supports use of the claims parameter."),
            SnippetUtils.fieldWithPath("service_documentation").description("URL of a page containing human-readable information that developers might want or need to know when using the OpenID Provider."),
            SnippetUtils.fieldWithPath("ui_locales_supported").description("Languages and scripts supported for the user interface.")
        );

        getMockMvc().perform(
            get("/.well-known/openid-configuration")
            .servletPath("/.well-known/openid-configuration")
            .accept(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andDo(document("{ClassName}/{methodName}",
                preprocessResponse(prettyPrint()),
                responseFields));
    }
}
