package com.tianzhu.identity.uaa.invitations;

import com.tianzhu.identity.uaa.authentication.UaaPrincipal;
import com.tianzhu.identity.uaa.authentication.manager.DynamicLdapAuthenticationManager;
import com.tianzhu.identity.uaa.authentication.manager.DynamicZoneAwareAuthenticationManager;
import com.tianzhu.identity.uaa.codestore.ExpiringCode;
import com.tianzhu.identity.uaa.codestore.ExpiringCodeStore;
import com.tianzhu.identity.uaa.constants.OriginKeys;
import com.tianzhu.identity.uaa.home.BuildInfo;
import com.tianzhu.identity.uaa.login.ThymeleafConfig;
import com.tianzhu.identity.uaa.provider.IdentityProvider;
import com.tianzhu.identity.uaa.provider.IdentityProviderProvisioning;
import com.tianzhu.identity.uaa.provider.OIDCIdentityProviderDefinition;
import com.tianzhu.identity.uaa.provider.SamlIdentityProviderDefinition;
import com.tianzhu.identity.uaa.provider.ldap.ExtendedLdapUserDetails;
import com.tianzhu.identity.uaa.scim.ScimUser;
import com.tianzhu.identity.uaa.scim.ScimUserProvisioning;
import com.tianzhu.identity.uaa.scim.exception.InvalidPasswordException;
import com.tianzhu.identity.uaa.scim.validate.PasswordValidator;
import com.tianzhu.identity.uaa.user.UaaAuthority;
import com.tianzhu.identity.uaa.user.UaaUser;
import com.tianzhu.identity.uaa.user.UaaUserDatabase;
import com.tianzhu.identity.uaa.util.JsonUtils;
import com.tianzhu.identity.uaa.zone.IdentityZone;
import com.tianzhu.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import java.net.URL;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static com.tianzhu.identity.uaa.codestore.ExpiringCodeType.INVITATION;
import static com.tianzhu.identity.uaa.constants.OriginKeys.LDAP;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = InvitationsControllerTest.ContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class InvitationsControllerTest {

    private MockMvc mockMvc;

    @Autowired
    ConfigurableWebApplicationContext webApplicationContext;

    @Autowired
    InvitationsService invitationsService;

    @Autowired
    ExpiringCodeStore expiringCodeStore;

    @Autowired
    PasswordValidator passwordValidator;

    @Autowired
    ClientDetailsService clientDetailsService;

    @Autowired
    IdentityProviderProvisioning providerProvisioning;

    @Autowired
    UaaUserDatabase userDatabase;

    @Autowired
    DynamicZoneAwareAuthenticationManager zoneAwareAuthenticationManager;

    @Autowired
    ScimUserProvisioning scimUserProvisioning;

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .build();
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testAcceptInvitationsPage() throws Exception {
        Map<String,String> codeData = new HashMap<>();
        codeData.put("user_id", "user-id-001");
        codeData.put("email", "user@example.com");
        codeData.put("client_id", "client-id");
        codeData.put("redirect_uri", "blah.test.com");
        when(expiringCodeStore.retrieveCode("code", IdentityZoneHolder.get().getId())).thenReturn(createCode(codeData), null);
        when(expiringCodeStore.generateCode(ArgumentMatchers.anyString(), ArgumentMatchers.anyObject(), ArgumentMatchers.eq(INVITATION.name()), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(createCode(codeData));
        IdentityProvider provider = new IdentityProvider();
        provider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin(any(), any())).thenReturn(provider);

        mockMvc.perform(get("/invitations/accept").param("code", "code"))
            .andExpect(status().isOk())
            .andExpect(model().attribute("email", "user@example.com"))
            .andExpect(model().attribute("code", "code"))
            .andExpect(view().name("invitations/accept_invite"));

        UaaPrincipal principal = ((UaaPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        assertTrue(SecurityContextHolder.getContext().getAuthentication() instanceof AnonymousAuthenticationToken);
        assertEquals("user-id-001", principal.getId());
        assertEquals("user@example.com", principal.getName());
        assertEquals("user@example.com", principal.getEmail());

        mockMvc.perform(get("/invitations/accept").param("code", "code"))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("invitations/accept_invite"))
            .andExpect(model().attribute("error_message_code", "code_expired"));
    }

    @Test
    public void incorrectCodeIntent() throws Exception {
        Map<String,String> codeData = new HashMap<>();
        codeData.put("user_id", "user-id-001");
        codeData.put("email", "user@example.com");
        codeData.put("client_id", "client-id");
        codeData.put("redirect_uri", "blah.test.com");
        when(expiringCodeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), "incorrect-code-intent"));;

        MockHttpServletRequestBuilder get = get("/invitations/accept")
            .param("code", "the_secret_code");

        mockMvc.perform(get).andExpect(status().isUnprocessableEntity());
    }


    @Test
    public void acceptInvitePage_for_unverifiedSamlUser() throws Exception {
        Map<String,String> codeData = getInvitationsCode("test-saml");
        when(expiringCodeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(createCode(codeData));
        when(expiringCodeStore.generateCode(ArgumentMatchers.anyString(), ArgumentMatchers.anyObject(), ArgumentMatchers.eq(INVITATION.name()), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(createCode(codeData));
        IdentityProvider provider = new IdentityProvider();
        SamlIdentityProviderDefinition definition = new SamlIdentityProviderDefinition()
            .setMetaDataLocation("http://test.saml.com")
            .setIdpEntityAlias("test-saml")
            .setNameID("test")
            .setLinkText("testsaml")
            .setIconUrl("test.com")
            .setZoneId(IdentityZone.getUaa().getId());
        provider.setConfig(definition);
        provider.setType(OriginKeys.SAML);
        when(providerProvisioning.retrieveByOrigin(ArgumentMatchers.eq("test-saml"), ArgumentMatchers.anyString())).thenReturn(provider);
        MockHttpServletRequestBuilder get = get("/invitations/accept")
                .param("code", "the_secret_code");

        MvcResult result = mockMvc.perform(get)
                .andExpect(redirectedUrl("/saml/discovery?returnIDParam=idp&entityID=sp-entity-id&idp=test-saml&isPassive=true"))
                .andReturn();

        assertEquals(true, result.getRequest().getSession().getAttribute("IS_INVITE_ACCEPTANCE"));
        assertEquals("user-id-001", result.getRequest().getSession().getAttribute("user_id"));
    }

    @Test
    public void acceptInvitePage_for_unverifiedOIDCUser() throws Exception {
        Map<String,String> codeData = getInvitationsCode("test-oidc");
        when(expiringCodeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(createCode(codeData));
        when(expiringCodeStore.generateCode(ArgumentMatchers.anyString(), ArgumentMatchers.anyObject(), ArgumentMatchers.eq(INVITATION.name()), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(createCode(codeData));

        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setAuthUrl(new URL("https://oidc10.auth.url"));

        IdentityProvider provider = new IdentityProvider();
        provider.setConfig(definition);
        provider.setType(OriginKeys.OIDC10);
        when(providerProvisioning.retrieveByOrigin(ArgumentMatchers.eq("test-oidc"), ArgumentMatchers.anyString())).thenReturn(provider);

        MockHttpServletRequestBuilder get = get("/invitations/accept")
                .param("code", "the_secret_code");

        MvcResult result = mockMvc.perform(get)
                .andExpect(redirectedUrl("https://oidc10.auth.url?client_id=" + definition.getRelyingPartyId() + "&response_type=code&redirect_uri=http://null/login/callback/" + provider.getOriginKey()))
                .andReturn();

        assertEquals(true, result.getRequest().getSession().getAttribute("IS_INVITE_ACCEPTANCE"));
        assertEquals("user-id-001", result.getRequest().getSession().getAttribute("user_id"));
    }

    @Test
    public void acceptInvitePage_for_unverifiedLdapUser() throws Exception {
        Map<String, String> codeData = getInvitationsCode(LDAP);
        when(expiringCodeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(createCode(codeData));
        when(expiringCodeStore.generateCode(ArgumentMatchers.anyString(), ArgumentMatchers.anyObject(), ArgumentMatchers.eq(INVITATION.name()), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(createCode(codeData));

        IdentityProvider provider = new IdentityProvider();
        provider.setType(LDAP);
        when(providerProvisioning.retrieveByOrigin(ArgumentMatchers.eq(LDAP), ArgumentMatchers.anyString())).thenReturn(provider);

        MockHttpServletRequestBuilder get = get("/invitations/accept")
                .param("code", "the_secret_code");

        mockMvc.perform(get)
                .andExpect(view().name("invitations/accept_invite"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Email: " + "user@example.com")))
                .andExpect(content().string(containsString("Sign in with enterprise credentials:")))
                .andExpect(content().string(containsString("username")))
                .andExpect(model().attribute("code", "code"))
                .andReturn();
    }

    private Map<String, String> getInvitationsCode(String origin) {
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-id-001");
        codeData.put("email", "user@example.com");
        codeData.put("client_id", "client-id");
        codeData.put("redirect_uri", "blah.test.com");
        codeData.put("origin", origin);
        return codeData;
    }

    @Test
    public void unverifiedLdapUser_acceptsInvite_byLoggingIn() throws Exception {
        Map<String, String> codeData = getInvitationsCode(LDAP);
        when(expiringCodeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        when(expiringCodeStore.generateCode(ArgumentMatchers.anyString(), ArgumentMatchers.anyObject(), ArgumentMatchers.eq(null), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        DynamicLdapAuthenticationManager ldapAuthenticationManager = mock(DynamicLdapAuthenticationManager.class);
        when(zoneAwareAuthenticationManager.getLdapAuthenticationManager(ArgumentMatchers.anyObject(), ArgumentMatchers.anyObject())).thenReturn(ldapAuthenticationManager);

        AuthenticationManager ldapActual = mock(AuthenticationManager.class);
        when(ldapAuthenticationManager.getLdapManagerActual()).thenReturn(ldapActual);

        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        when(ldapActual.authenticate(ArgumentMatchers.anyObject())).thenReturn(auth);

        ExtendedLdapUserDetails extendedLdapUserDetails = mock(ExtendedLdapUserDetails.class);

        when(auth.getPrincipal()).thenReturn(extendedLdapUserDetails);
        when(extendedLdapUserDetails.getEmailAddress()).thenReturn("user@example.com");
        when(extendedLdapUserDetails.getUsername()).thenReturn("test-ldap-user");

        ScimUser invitedUser = new ScimUser("user-id-001", "user@example.com", "g", "f");
        invitedUser.setPrimaryEmail("user@example.com");

        when(scimUserProvisioning.retrieve("user-id-001", IdentityZoneHolder.get().getId())).thenReturn(invitedUser);
        when(invitationsService.acceptInvitation(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())).thenReturn(new InvitationsService.AcceptedInvitation("blah.test.com", new ScimUser()));
        when(expiringCodeStore.generateCode(ArgumentMatchers.anyString(), ArgumentMatchers.anyObject(), ArgumentMatchers.eq(null), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));

        mockMvc.perform(post("/invitations/accept_enterprise.do")
                .param("enterprise_username", "test-ldap-user")
                .param("enterprise_password", "password")
                .param("enterprise_email", "email")
                .param("code", "the_secret_code"))
                .andExpect(redirectedUrl("blah.test.com"))
                .andReturn();

        verify(ldapActual).authenticate(ArgumentMatchers.anyObject());
        ArgumentCaptor<ScimUser> userArgumentCaptor = ArgumentCaptor.forClass(ScimUser.class);
        verify(scimUserProvisioning).update(ArgumentMatchers.anyString(), userArgumentCaptor.capture(), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()));
        ScimUser value = userArgumentCaptor.getValue();
        assertEquals("test-ldap-user", value.getUserName());
        assertEquals("user@example.com", value.getPrimaryEmail());
        verify(ldapAuthenticationManager).authenticate(ArgumentMatchers.anyObject());
    }

    @Test
    public void unverifiedLdapUser_acceptsInvite_byLoggingIn_bad_credentials() throws Exception {
        Map<String, String> codeData = getInvitationsCode("ldap");
        when(expiringCodeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        when(expiringCodeStore.generateCode(ArgumentMatchers.anyString(), ArgumentMatchers.anyObject(), ArgumentMatchers.eq(null), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        DynamicLdapAuthenticationManager ldapAuthenticationManager = mock(DynamicLdapAuthenticationManager.class);
        when(zoneAwareAuthenticationManager.getLdapAuthenticationManager(ArgumentMatchers.anyObject(), ArgumentMatchers.anyObject())).thenReturn(ldapAuthenticationManager);

        AuthenticationManager ldapActual = mock(AuthenticationManager.class);
        when(ldapAuthenticationManager.getLdapManagerActual()).thenReturn(ldapActual);

        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        when(ldapActual.authenticate(ArgumentMatchers.anyObject())).thenThrow(new BadCredentialsException("bad creds"));

        mockMvc.perform(post("/invitations/accept_enterprise.do")
          .param("enterprise_username", "test-ldap-user")
          .param("enterprise_password", "password")
          .param("enterprise_email", "email")
          .param("code", "the_secret_code"))
          .andExpect(model().attribute("ldap", true))
          .andExpect(model().attribute("email", "email"))
          .andExpect(model().attribute("error_message", "bad_credentials"))
          .andReturn();
    }

    @Test
    public void unverifiedLdapUser_acceptsInvite_byLoggingIn_whereEmailDoesNotMatchAuthenticatedEmail() throws Exception {
        Map<String, String> codeData = getInvitationsCode(LDAP);
        when(expiringCodeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        DynamicLdapAuthenticationManager ldapAuthenticationManager = mock(DynamicLdapAuthenticationManager.class);
        when(zoneAwareAuthenticationManager.getLdapAuthenticationManager(ArgumentMatchers.anyObject(), ArgumentMatchers.anyObject())).thenReturn(ldapAuthenticationManager);

        AuthenticationManager ldapActual = mock(AuthenticationManager.class);
        when(ldapAuthenticationManager.getLdapManagerActual()).thenReturn(ldapActual);
        Authentication auth = mock(Authentication.class);
        when(ldapActual.authenticate(ArgumentMatchers.anyObject())).thenReturn(auth);

        ExtendedLdapUserDetails extendedLdapUserDetails = mock(ExtendedLdapUserDetails.class);
        when(auth.getPrincipal()).thenReturn(extendedLdapUserDetails);
        when(extendedLdapUserDetails.getEmailAddress()).thenReturn("different-email@example.com");

        ScimUser invitedUser = new ScimUser("user-id-001", "user@example.com", "g", "f");
        invitedUser.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.retrieve("user-id-001", IdentityZoneHolder.get().getId())).thenReturn(invitedUser);
        when(expiringCodeStore.generateCode(ArgumentMatchers.anyString(), ArgumentMatchers.anyObject(), ArgumentMatchers.eq(null), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));

        mockMvc.perform(post("/invitations/accept_enterprise.do")
                .param("enterprise_username", "test-ldap-user")
                .param("enterprise_password", "password")
                .param("enterprise_email", "email")
                .param("code", "the_secret_code"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(view().name("invitations/accept_invite"))
                .andExpect(content().string(containsString("Email: " + "user@example.com")))
                .andExpect(content().string(containsString("Sign in with enterprise credentials:")))
                .andExpect(content().string(containsString("username")))
                .andExpect(model().attribute("code", "code"))
                .andExpect(model().attribute("error_message", "invite.email_mismatch"))
                .andReturn();

        verify(ldapActual).authenticate(ArgumentMatchers.anyObject());
    }

    @Test
    public void acceptInvitePage_for_verifiedUser() throws Exception {
        UaaUser user = new UaaUser("user@example.com", "", "user@example.com", "Given", "family");
        user.modifyId("verified-user");
        user.setVerified(true);
        when(userDatabase.retrieveUserById("verified-user")).thenReturn(user);
        Map<String,String> codeData = new HashMap<>();
        codeData.put("user_id", "verified-user");
        codeData.put("email", "user@example.com");

        when(expiringCodeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(createCode(codeData), null);
        when(expiringCodeStore.generateCode(ArgumentMatchers.anyString(), ArgumentMatchers.anyObject(), ArgumentMatchers.eq(INVITATION.name()), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(createCode(codeData));
        when(invitationsService.acceptInvitation(ArgumentMatchers.anyString(), ArgumentMatchers.eq(""))).thenReturn(new InvitationsService.AcceptedInvitation("blah.test.com", new ScimUser()));
        IdentityProvider provider = new IdentityProvider();
        provider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())).thenReturn(provider);
        MockHttpServletRequestBuilder get = get("/invitations/accept")
                .param("code", "the_secret_code");

        mockMvc.perform(get)
                .andExpect(redirectedUrl("blah.test.com"));
    }

    private ExpiringCode createCode(Map<String, String> codeData) {
        return new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), INVITATION.name());
    }

    @Test
    public void incorrectGeneratedCodeIntent_for_verifiedUser() throws Exception {
        UaaUser user = new UaaUser("user@example.com", "", "user@example.com", "Given", "family");
        user.modifyId("verified-user");
        user.setVerified(true);
        when(userDatabase.retrieveUserById("verified-user")).thenReturn(user);

        Map<String,String> codeData = new HashMap<>();
        codeData.put("user_id", "verified-user");
        codeData.put("email", "user@example.com");
        when(expiringCodeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), "incorrect-code-intent"));
        when(expiringCodeStore.generateCode(ArgumentMatchers.anyString(), ArgumentMatchers.anyObject(), ArgumentMatchers.eq(null), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), "incorrect-code-intent"));
        doThrow(new HttpClientErrorException(BAD_REQUEST)).when(invitationsService).acceptInvitation(ArgumentMatchers.eq("incorrect-code-intent"), ArgumentMatchers.eq(""));

        MockHttpServletRequestBuilder get = get("/invitations/accept")
            .param("code", "the_secret_code");

        mockMvc.perform(get).andExpect(status().isUnprocessableEntity());
    }

    @Test
    public void testAcceptInvitePageWithExpiredCode() throws Exception {
        when(expiringCodeStore.retrieveCode(ArgumentMatchers.anyString(), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(null);
        MockHttpServletRequestBuilder get = get("/invitations/accept").param("code", "the_secret_code");
        mockMvc.perform(get)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(model().attribute("error_message_code", "code_expired"))
            .andExpect(view().name("invitations/accept_invite"))
            .andExpect(xpath("//*[@class='email-display']").doesNotExist())
            .andExpect(xpath("//form").doesNotExist());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void missing_code() throws Exception {
        MockHttpServletRequestBuilder post = startAcceptInviteFlow("a", "a");

        when(expiringCodeStore.retrieveCode("thecode", IdentityZoneHolder.get().getId())).thenReturn(null);

        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin("uaa", "uaa")).thenReturn(identityProvider);
        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(model().attribute("error_message_code", "code_expired"))
            .andExpect(view().name("invitations/accept_invite"));
        verify(expiringCodeStore).retrieveCode("thecode", IdentityZoneHolder.get().getId());
        verify(expiringCodeStore, never()).generateCode(ArgumentMatchers.anyString(), ArgumentMatchers.anyObject(), ArgumentMatchers.anyString(), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()));
        verify(invitationsService, never()).acceptInvitation(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());

    }

    @Test
    public void invalid_principal_id() throws Exception {
        MockHttpServletRequestBuilder post = startAcceptInviteFlow("a", "a");

        Map<String,String> codeData = getInvitationsCode(OriginKeys.UAA);
        codeData.put("user_id", "invalid id");
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        when(expiringCodeStore.retrieveCode("thecode", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name()), null);

        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin("uaa", "uaa")).thenReturn(identityProvider);
        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(model().attribute("error_message_code", "code_expired"))
            .andExpect(view().name("invitations/accept_invite"));
        verify(expiringCodeStore).retrieveCode("thecode", IdentityZoneHolder.get().getId());
        verify(expiringCodeStore, never()).generateCode(ArgumentMatchers.anyString(), ArgumentMatchers.anyObject(), ArgumentMatchers.anyString(), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()));
        verify(invitationsService, never()).acceptInvitation(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());

    }

    @Test
    public void testAcceptInviteWithContraveningPassword() throws Exception {
        doThrow(new InvalidPasswordException(Arrays.asList("Msg 2c", "Msg 1c"))).when(passwordValidator).validate("a");
        MockHttpServletRequestBuilder post = startAcceptInviteFlow("a", "a");

        Map<String,String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        when(expiringCodeStore.retrieveCode("thecode", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name()), null);
        when(expiringCodeStore.retrieveCode("thenewcode", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name()), null);
        when(expiringCodeStore.generateCode(ArgumentMatchers.eq(codeDataString), any(), ArgumentMatchers.eq(INVITATION.name()), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(
            new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name()),
            new ExpiringCode("thenewcode2", new Timestamp(1), codeDataString, INVITATION.name())
        );

        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin("uaa", "uaa")).thenReturn(identityProvider);
        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(model().attribute("error_message", "Msg 1c Msg 2c"))
            .andExpect(model().attribute("code", "thenewcode2"))
            .andExpect(view().name("redirect:accept"));
        verify(expiringCodeStore).retrieveCode("thecode", IdentityZoneHolder.get().getId());
        verify(expiringCodeStore, times(2)).generateCode(ArgumentMatchers.anyString(), ArgumentMatchers.anyObject(), ArgumentMatchers.anyString(), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()));
        verify(invitationsService, never()).acceptInvitation(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());
    }

    @Test
    public void testAcceptInvite() throws Exception {
        ScimUser user = new ScimUser("user-id-001", "user@example.com","fname", "lname");
        user.setPrimaryEmail(user.getUserName());
        MockHttpServletRequestBuilder post = startAcceptInviteFlow("passw0rd","passw0rd");

        Map<String,String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        ExpiringCode thecode = new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name());
        ExpiringCode thenewcode = new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name());
        ExpiringCode thenewcode2 = new ExpiringCode("thenewcode2", new Timestamp(1), codeDataString, INVITATION.name());
        when(expiringCodeStore.retrieveCode("thecode", IdentityZoneHolder.get().getId())).thenReturn(thecode, null);
        when(expiringCodeStore.retrieveCode("thenewcode", IdentityZoneHolder.get().getId())).thenReturn(thenewcode, null);
        when(expiringCodeStore.generateCode(ArgumentMatchers.eq(codeDataString), any(), ArgumentMatchers.eq(INVITATION.name()), ArgumentMatchers.eq(IdentityZoneHolder.get().getId())))
            .thenReturn(thenewcode)
            .thenReturn(thenewcode2);

        when(invitationsService.acceptInvitation(ArgumentMatchers.anyString(), ArgumentMatchers.eq("passw0rd"))).thenReturn(new InvitationsService.AcceptedInvitation("/home", user));

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/home"));

        verify(invitationsService).acceptInvitation(ArgumentMatchers.anyString(), ArgumentMatchers.eq("passw0rd"));
    }

    private MockHttpServletRequestBuilder startAcceptInviteFlow(String password, String passwordConfirmation) {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", OriginKeys.UAA, null, IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);

        return post("/invitations/accept.do")
            .param("code","thecode")
            .param("password", password)
            .param("password_confirmation", passwordConfirmation);
    }

    @Test
    public void acceptInviteWithValidClientRedirect() throws Exception {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", OriginKeys.UAA, null,IdentityZoneHolder.get().getId());
        ScimUser user = new ScimUser(uaaPrincipal.getId(), uaaPrincipal.getName(),"fname", "lname");
        user.setPrimaryEmail(user.getUserName());

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);

        Map<String,String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        when(expiringCodeStore.retrieveCode("thecode", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name()), null);
        when(expiringCodeStore.generateCode(ArgumentMatchers.eq(codeDataString), any(), ArgumentMatchers.eq(INVITATION.name()), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name()));
        when(invitationsService.acceptInvitation(ArgumentMatchers.anyString(), ArgumentMatchers.eq("password"))).thenReturn(new InvitationsService.AcceptedInvitation("valid.redirect.com", user));

        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
            .param("password", "password")
            .param("password_confirmation", "password")
            .param("code", "thecode");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("valid.redirect.com"));
    }

    @Test
    public void acceptInviteWithInvalidClientRedirect() throws Exception {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", OriginKeys.UAA, null,IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);

        ScimUser user = new ScimUser(uaaPrincipal.getId(), uaaPrincipal.getName(),"fname", "lname");
        user.setPrimaryEmail(user.getUserName());

        Map<String,String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        when(expiringCodeStore.retrieveCode("thecode", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name()), null);
        when(expiringCodeStore.generateCode(ArgumentMatchers.eq(codeDataString), any(), ArgumentMatchers.eq(INVITATION.name()), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name()));

        when(invitationsService.acceptInvitation(ArgumentMatchers.anyString(), ArgumentMatchers.eq("password"))).thenReturn(new InvitationsService.AcceptedInvitation("/home", user));

        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
            .param("code","thecode")
            .param("password", "password")
            .param("password_confirmation", "password");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/home"));
    }

    @Test
    public void invalidCodeOnAcceptPost() throws Exception {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", OriginKeys.UAA, null,IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);

        Map<String,String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        when(expiringCodeStore.retrieveCode("thecode", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name()), null);
        when(expiringCodeStore.generateCode(ArgumentMatchers.eq(codeDataString), any(), ArgumentMatchers.eq(INVITATION.name()), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name()));

        doThrow(new HttpClientErrorException(BAD_REQUEST)).when(invitationsService).acceptInvitation(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());

        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
            .param("code","thecode")
            .param("password", "password")
            .param("password_confirmation", "password");

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(model().attribute("error_message_code", "code_expired"))
            .andExpect(view().name("invitations/accept_invite"));
    }

    @Test
    public void testAcceptInviteWithoutMatchingPasswords() throws Exception {
        MockHttpServletRequestBuilder post = startAcceptInviteFlow("a","b");

        Map<String,String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        when(expiringCodeStore.retrieveCode("thecode", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name()), null);
        when(expiringCodeStore.retrieveCode("thenewcode", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name()), null);
        when(expiringCodeStore.generateCode(ArgumentMatchers.eq(codeDataString), any(), ArgumentMatchers.eq(INVITATION.name()), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()))).thenReturn(
            new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name()),
            new ExpiringCode("thenewcode2", new Timestamp(1), codeDataString, INVITATION.name())
        );


        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin("uaa", "uaa")).thenReturn(identityProvider);
        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(model().attribute("error_message_code", "form_error"))
            .andExpect(model().attribute("code", "thenewcode2"))
            .andExpect(view().name("redirect:accept"));
        verify(expiringCodeStore).retrieveCode("thecode", IdentityZoneHolder.get().getId());
        verify(expiringCodeStore, times(2)).generateCode(ArgumentMatchers.anyString(), ArgumentMatchers.anyObject(), ArgumentMatchers.anyString(), ArgumentMatchers.eq(IdentityZoneHolder.get().getId()));
        verify(invitationsService, never()).acceptInvitation(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());
    }


    @Configuration
    @EnableWebMvc
    @Import(ThymeleafConfig.class)
    static class ContextConfiguration extends WebMvcConfigurerAdapter {

        @Override
        public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
            configurer.enable();
        }

        @Bean
        BuildInfo buildInfo() {
            return new BuildInfo();
        }

        @Bean
        public UaaUserDatabase userDatabase() {
            UaaUserDatabase userDatabase = mock(UaaUserDatabase.class);
            UaaUser user = new UaaUser("user@example.com","","user@example.com","Given","family");
            user = user.modifyId("user-id-001");
            when (userDatabase.retrieveUserById(user.getId())).thenReturn(user);
            return userDatabase;
        }

        @Bean
        public DynamicZoneAwareAuthenticationManager dynamicZoneAwareAuthenticationManager() {
            return mock(DynamicZoneAwareAuthenticationManager.class);
        }

        @Bean
        public ScimUserProvisioning userProvisioning() {
            return mock(ScimUserProvisioning.class);
        }

        @Bean
        public ResourceBundleMessageSource messageSource() {
            ResourceBundleMessageSource resourceBundleMessageSource = new ResourceBundleMessageSource();
            resourceBundleMessageSource.setBasename("messages");
            return resourceBundleMessageSource;
        }

        @Bean
        InvitationsService invitationsService() {
            return mock(InvitationsService.class);
        }

        @Bean
        InvitationsController invitationsController(InvitationsService invitationsService,
                                                    ExpiringCodeStore codeStore,
                                                    PasswordValidator passwordPolicyValidator,
                                                    IdentityProviderProvisioning providerProvisioning,
                                                    UaaUserDatabase userDatabase,
                                                    ScimUserProvisioning provisioning,
                                                    DynamicZoneAwareAuthenticationManager zoneAwareAuthenticationManager) {
            InvitationsController result = new InvitationsController(invitationsService);
            result.setExpiringCodeStore(codeStore);
            result.setPasswordValidator(passwordPolicyValidator);
            result.setProviderProvisioning(providerProvisioning);
            result.setUserDatabase(userDatabase);
            result.setSpEntityID("sp-entity-id");
            result.setZoneAwareAuthenticationManager(zoneAwareAuthenticationManager);
            result.setUserProvisioning(provisioning);
            return result;
        }

        @Bean
        ExpiringCodeStore expiringCodeStore() {
            return mock(ExpiringCodeStore.class);
        }

        @Bean
        PasswordValidator uaaPasswordValidator() { return mock(PasswordValidator.class); }

        @Bean
        IdentityProviderProvisioning providerProvisioning() {

            return mock (IdentityProviderProvisioning.class);
        }

        @Bean
        ClientDetailsService clientDetailsService() {
            return mock(ClientDetailsService.class);
        }

        @Bean
        DynamicZoneAwareAuthenticationManager zoneAwareAuthenticationManager() {
            return mock(DynamicZoneAwareAuthenticationManager.class);
        }

    }
}
