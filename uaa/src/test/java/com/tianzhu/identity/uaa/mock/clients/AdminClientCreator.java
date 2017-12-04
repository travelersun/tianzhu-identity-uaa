package com.tianzhu.identity.uaa.mock.clients;

import com.tianzhu.identity.uaa.mock.InjectedMockContextTest;
import com.tianzhu.identity.uaa.mock.util.ClientDetailsHelper;
import com.tianzhu.identity.uaa.client.InvalidClientDetailsException;
import com.tianzhu.identity.uaa.oauth.client.ClientDetailsModification;
import com.tianzhu.identity.uaa.test.UaaTestAccounts;
import com.tianzhu.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public abstract class AdminClientCreator extends InjectedMockContextTest {
    protected String adminToken = null;
    protected UaaTestAccounts testAccounts;
    
    public static final String SECRET = "secret";

    @Before
    public void initAdminToken() throws Exception {
        testAccounts = UaaTestAccounts.standard(null);
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "clients.admin clients.read clients.write clients.secret scim.read scim.write");
    }

    protected ClientDetailsModification createBaseClient(String id, String clientSecret, Collection<String> grantTypes, List<String> authorities, List<String> scopes) {
        if (id==null) {
            id = new RandomValueStringGenerator().generate();
        }
        if (grantTypes==null) {
            grantTypes = Collections.singleton("client_credentials");
        }
        ClientDetailsModification client = new ClientDetailsModification();
        client.setClientId(id);
        client.setScope(scopes);
        client.setAuthorizedGrantTypes(grantTypes);
        if(authorities != null) {
            client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList(String.join(",", authorities)));
        }
        client.setClientSecret(clientSecret);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("foo", "bar");
        additionalInformation.put("name", makeClientName(id));
        client.setAdditionalInformation(additionalInformation);
        client.setRegisteredRedirectUri(Collections.singleton("http://some.redirect.url.com"));
        return client;
    }

    protected ClientDetails createClient(String token, String id, String clientSecret, Collection<String> grantTypes) throws Exception {
        BaseClientDetails client = createBaseClient(id, clientSecret, grantTypes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(client));
        getMockMvc().perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }
    

    protected ClientDetails createClientWithExpect(String token, String id, String clientSecret, Collection<String> grantTypes, ResultMatcher status) throws Exception {
        BaseClientDetails client = createBaseClient(id, clientSecret, grantTypes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(client));
        getMockMvc().perform(createClientPost).andExpect(status);
        return getClient(client.getClientId());
    }

    protected ClientDetails createClientAdminsClient(String token) throws Exception {
        List<String> scopes = Arrays.asList("oauth.approvals", "clients.admin");
        BaseClientDetails client = createBaseClient(null, SECRET, Arrays.asList("password", "client_credentials"), scopes, scopes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(client));
        getMockMvc().perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }

    protected ClientDetails createReadWriteClient(String token) throws Exception {
        List<String> scopes = Arrays.asList("oauth.approvals","clients.read","clients.write");
        BaseClientDetails client = createBaseClient(null, SECRET, Arrays.asList("password","client_credentials"), scopes, scopes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(client));
        getMockMvc().perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }

    protected ClientDetails createAdminClient(String token) throws Exception {
        List<String> scopes = Arrays.asList("uaa.admin","oauth.approvals","clients.read","clients.write");
        BaseClientDetails client = createBaseClient(null, SECRET, Arrays.asList("password","client_credentials"), scopes, scopes);

        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(client));
        getMockMvc().perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }


    protected ClientDetailsModification createBaseClient(String id, String clientSecret, Collection<String> grantTypes) {
        return createBaseClient(id, clientSecret, grantTypes, Collections.singletonList("uaa.none"), Arrays.asList("foo", "bar", "oauth.approvals"));
    }

    protected ClientDetailsModification[] createBaseClients(int length, String clientSecret, Collection<String> grantTypes) {
        ClientDetailsModification[] result = new ClientDetailsModification[length];
        for (int i=0; i<result.length; i++) {
            result[i] = createBaseClient(null, clientSecret, grantTypes);
        }
        return result;
    }

    protected ClientDetails getClient(String id) throws Exception {
        MockHttpServletResponse response = getClientHttpResponse(id);
        return getClientResponseAsClientDetails(response);
    }
    protected String toString(Object client) throws Exception {
        return JsonUtils.writeValueAsString(client);
    }
    protected String toString(Object[] clients) throws Exception {
        return JsonUtils.writeValueAsString(clients);
    }

    protected MockHttpServletResponse getClientHttpResponse(String id) throws Exception {
        MockHttpServletRequestBuilder getClient = get("/oauth/clients/" + id)
            .header("Authorization", "Bearer " + adminToken)
            .accept(APPLICATION_JSON);
        ResultActions result = getMockMvc().perform(getClient);
        return result.andReturn().getResponse();
    }


    protected ClientDetails createApprovalsLoginClient(String token) throws Exception {
        List<String> scopes = Arrays.asList("uaa.admin","oauth.approvals","oauth.login");
        BaseClientDetails client = createBaseClient(null, SECRET, Arrays.asList("password","client_credentials"), scopes, scopes);

        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(client));
        getMockMvc().perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }

    protected ClientDetails getClientResponseAsClientDetails(MockHttpServletResponse response) throws Exception {
        int responseCode = response.getStatus();
        HttpStatus status = HttpStatus.valueOf(responseCode);
        String body = response.getContentAsString();
        if (status == HttpStatus.OK) {
            return ClientDetailsHelper.clientFromString(body);
        } else if ( status == HttpStatus.NOT_FOUND) {
            return null;
        } else {
            throw new InvalidClientDetailsException(status+" : "+body);
        }
    }

    protected static String makeClientName(String id) {
        return "Client " + id;
    }
}
