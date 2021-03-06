package com.tianzhu.identity.uaa.integration;

import com.fasterxml.jackson.core.type.TypeReference;
import com.tianzhu.identity.uaa.integration.util.IntegrationTestUtils;
import com.tianzhu.identity.uaa.ServerRunning;
import com.tianzhu.identity.uaa.oauth.client.ClientConstants;
import com.tianzhu.identity.uaa.test.UaaTestAccounts;
import com.tianzhu.identity.uaa.util.JsonUtils;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.springframework.http.MediaType.APPLICATION_JSON;

public class PasswordGrantIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    RandomValueStringGenerator generator = new RandomValueStringGenerator(36);

    @Test
    public void testUserLoginViaPasswordGrant() throws Exception {
        ResponseEntity<String> responseEntity = makePasswordGrantRequest(testAccounts.getUserName(), testAccounts.getPassword(), "cf", "");
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    }

    @Test
    public void password_grant_returns_correct_error() throws Exception {
        BaseClientDetails client = addUserGroupsRequiredClient();
        ResponseEntity<String> responseEntity = makePasswordGrantRequest(testAccounts.getUserName(), testAccounts.getPassword(), client.getClientId(), "secret");
        assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        assertEquals("application/json;charset=UTF-8", responseEntity.getHeaders().get("Content-Type").get(0));
        Map<String, Object> errors = JsonUtils.readValue(responseEntity.getBody(), new TypeReference<Map<String,Object>>() {});
        assertEquals("User does not meet the client's required group criteria.", errors.get("error_description"));
        assertEquals("invalid_scope", errors.get("error"));
    }

    protected BaseClientDetails addUserGroupsRequiredClient() throws Exception {
        String adminToken = IntegrationTestUtils.getClientCredentialsToken(
            serverRunning.getBaseUrl(),
            "admin",
            "adminsecret"
        );
        BaseClientDetails client = new BaseClientDetails(
            generator.generate(),
            null,
            "openid",
            "password",
            null
        );
        client.setClientSecret("secret");
        Map<String, Object> additional = new HashMap();
        additional.put(ClientConstants.REQUIRED_USER_GROUPS, Arrays.asList("non.existent"));
        client.setAdditionalInformation(additional);

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(APPLICATION_JSON));
        headers.add("Authorization", "Bearer "+adminToken);
        headers.setContentType(APPLICATION_JSON);

        HttpEntity<String> request = new HttpEntity<>(JsonUtils.writeValueAsString(client), headers);

        ResponseEntity<String> response = new RestTemplate().postForEntity(serverRunning.getUrl("/oauth/clients"), request, String.class);
        assertEquals(201, response.getStatusCodeValue());

        return JsonUtils.readValue(response.getBody(), BaseClientDetails.class);
    }

    private ResponseEntity<String> makePasswordGrantRequest(String userName, String password, String clientId, String clientSecret) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(APPLICATION_JSON));
        headers.add("Authorization", testAccounts.getAuthorizationHeader(clientId, clientSecret));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("username", userName);
        params.add("password", password);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        RestTemplate template = getRestTemplate();
        return template.postForEntity(serverRunning.getAccessTokenUri(), request, String.class);
    }

    private RestTemplate getRestTemplate() {
        RestTemplate template = new RestTemplate();
        template.setErrorHandler(new ResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return response.getRawStatusCode()>=500;
            }

            @Override
            public void handleError(ClientHttpResponse response) throws IOException {

            }
        });
        return template;
    }
}
