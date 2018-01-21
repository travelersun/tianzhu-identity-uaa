package com.tianzhu.identity.uaa.appconfig.filter;

import com.tianzhu.identity.uaa.authentication.*;
import com.tianzhu.identity.uaa.codestore.ExpiringCodeStore;
import com.tianzhu.identity.uaa.login.AccountSavingAuthenticationSuccessHandler;
import com.tianzhu.identity.uaa.provider.oauth.XOAuthAuthenticationFilter;
import com.tianzhu.identity.uaa.provider.oauth.XOAuthAuthenticationManager;
import com.tianzhu.identity.uaa.user.UaaUserDatabase;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;

@Configuration
public class OauthFilterBean {

    @Bean
    public PasscodeAuthenticationFilter passcodeAuthenticationFilter(@Qualifier("userDatabase") UaaUserDatabase uaaUserDatabase,
                                                                     @Qualifier("zoneAwareAuthzAuthenticationManager") AuthenticationManager authenticationManager,
                                                                     @Qualifier("authorizationRequestManager") OAuth2RequestFactory oAuth2RequestFactory,
                                                                     @Qualifier("codeStore") ExpiringCodeStore expiringCodeStore,
                                                                     @Qualifier("authenticationDetailsSource") AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource){
        PasscodeAuthenticationFilter passcodeAuthenticationFilter = new PasscodeAuthenticationFilter(uaaUserDatabase,authenticationManager,oAuth2RequestFactory,expiringCodeStore);
        passcodeAuthenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);

        passcodeAuthenticationFilter.setParameterNames(Arrays.asList("username","password","passcode","credentials","origin","user_id"));
        return passcodeAuthenticationFilter;
    }

    @Bean
    public ClientBasicAuthenticationFilter clientAuthenticationFilter(@Qualifier("clientAuthenticationManager") AuthenticationManager authenticationManager,
                                                                      @Qualifier("basicAuthenticationEntryPoint") AuthenticationEntryPoint authenticationEntryPoint,
                                                                      @Qualifier("authenticationDetailsSource") AuthenticationDetailsSource<javax.servlet.http.HttpServletRequest, ?> authenticationDetailsSource,
                                                                      @Qualifier("jdbcClientDetailsService") ClientDetailsService clientDetailsService){

        ClientBasicAuthenticationFilter clientAuthenticationFilter = new ClientBasicAuthenticationFilter(authenticationManager,authenticationEntryPoint);
        clientAuthenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
        clientAuthenticationFilter.setClientDetailsService(clientDetailsService);

        return clientAuthenticationFilter;
    }

    @Bean
    public ClientParametersAuthenticationFilter clientParameterAuthenticationFilter(@Qualifier("clientAuthenticationManager") AuthenticationManager authenticationManager,
                                                                      @Qualifier("basicAuthenticationEntryPoint") AuthenticationEntryPoint authenticationEntryPoint){

        ClientParametersAuthenticationFilter clientParameterAuthenticationFilter = new ClientParametersAuthenticationFilter();
        clientParameterAuthenticationFilter.setClientAuthenticationManager(authenticationManager);
        clientParameterAuthenticationFilter.setAuthenticationEntryPoint(authenticationEntryPoint);

        return clientParameterAuthenticationFilter;
    }

    @Bean
    public BackwardsCompatibleTokenEndpointAuthenticationFilter tokenEndpointAuthenticationFilter(@Qualifier("zoneAwareAuthzAuthenticationManager") AuthenticationManager authenticationManager,
                                                                                                  @Qualifier("authorizationRequestManager") OAuth2RequestFactory oAuth2RequestFactory,
                                                                                                  @Qualifier("samlWebSSOProcessingFilter") SAMLProcessingFilter samlAuthenticationFilter,
                                                                                                  @Qualifier("xOauthAuthenticationManager") XOAuthAuthenticationManager xoAuthAuthenticationManager,
                                                                                                  @Qualifier("basicAuthenticationEntryPoint") AuthenticationEntryPoint authenticationEntryPoint,
                                                                                                  @Qualifier("authenticationDetailsSource") AuthenticationDetailsSource<javax.servlet.http.HttpServletRequest, ?> authenticationDetailsSource
                                                                                                  ){

        BackwardsCompatibleTokenEndpointAuthenticationFilter tokenEndpointAuthenticationFilter = new BackwardsCompatibleTokenEndpointAuthenticationFilter(authenticationManager,oAuth2RequestFactory,samlAuthenticationFilter,xoAuthAuthenticationManager);
        tokenEndpointAuthenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
        tokenEndpointAuthenticationFilter.setAuthenticationEntryPoint(authenticationEntryPoint);

        return tokenEndpointAuthenticationFilter;
    }

    @Bean
    public AuthzAuthenticationFilter authzAuthenticationFilter(@Qualifier("zoneAwareAuthzAuthenticationManager") AuthenticationManager authenticationManager ){

        AuthzAuthenticationFilter authzAuthenticationFilter = new AuthzAuthenticationFilter(authenticationManager);
        authzAuthenticationFilter.setParameterNames(Arrays.asList("username","password","passcode","credentials"));

        return authzAuthenticationFilter;

    }

    @Bean
    public XOAuthAuthenticationFilter xOauthCallbackAuthenticationFilter(@Qualifier("xOauthAuthenticationManager") XOAuthAuthenticationManager xOAuthAuthenticationManager,
                                                                         @Qualifier("accountSavingAuthenticationSuccessHandler") AccountSavingAuthenticationSuccessHandler successHandler){

        XOAuthAuthenticationFilter xOauthCallbackAuthenticationFilter = new XOAuthAuthenticationFilter(xOAuthAuthenticationManager,successHandler);
        return xOauthCallbackAuthenticationFilter;

    }

}
