package com.tianzhu.identity.uaa.appconfig.filter;

import com.tianzhu.identity.uaa.authentication.AuthzAuthenticationFilter;
import com.tianzhu.identity.uaa.authentication.LoginClientParametersAuthenticationFilter;
import com.tianzhu.identity.uaa.authentication.LoginServerTokenEndpointFilter;
import com.tianzhu.identity.uaa.authentication.manager.LoginAuthenticationManager;
import com.tianzhu.identity.uaa.authentication.manager.ScopeAuthenticationFilter;
import com.tianzhu.identity.uaa.user.UaaUserDatabase;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

@Configuration
public class ServerSecurityFilterConfig {


    @Bean
    public ScopeAuthenticationFilter oauthLoginScopeAuthenticatingFilter(@Qualifier("oauthLoginAuthManager") AuthenticationManager oauthLoginAuthManager ){

        ScopeAuthenticationFilter oauthLoginScopeAuthenticatingFilter = new ScopeAuthenticationFilter();

        oauthLoginScopeAuthenticatingFilter.setAuthenticationManager(oauthLoginAuthManager);

        return oauthLoginScopeAuthenticatingFilter;

    }

    @Bean
    public LoginServerTokenEndpointFilter loginServerTokenEndpointAuthenticationFilter(@Qualifier("loginAuthenticationMgr") AuthenticationManager authenticationManager,
                                                                                       @Qualifier("authorizationRequestManager") OAuth2RequestFactory oAuth2RequestFactory,
                                                                                       @Qualifier("addNewUserParameters") List addNewUserParameters,
                                                                                       @Qualifier("authenticationDetailsSource") AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource){

        LoginServerTokenEndpointFilter loginServerTokenEndpointAuthenticationFilter = new LoginServerTokenEndpointFilter(authenticationManager,oAuth2RequestFactory,addNewUserParameters);


        loginServerTokenEndpointAuthenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);

        return  loginServerTokenEndpointAuthenticationFilter;
    }

    @Bean
    public LoginClientParametersAuthenticationFilter loginClientParameterAuthenticationFilter(@Qualifier("clientAuthenticationManager") AuthenticationManager clientAuthenticationManager){

        LoginClientParametersAuthenticationFilter loginClientParameterAuthenticationFilter = new LoginClientParametersAuthenticationFilter();
        loginClientParameterAuthenticationFilter.setClientAuthenticationManager(clientAuthenticationManager);
        return  loginClientParameterAuthenticationFilter;
    }

    @Bean
    public AuthzAuthenticationFilter loginAuthenticationFilter(@Qualifier("loginAuthenticationMgr") AuthenticationManager authenticationManager,
                                                               @Qualifier("addNewUserParameters") List parameterNames){

        AuthzAuthenticationFilter loginAuthenticationFilter = new AuthzAuthenticationFilter(authenticationManager);
        loginAuthenticationFilter.setParameterNames(parameterNames);
        return  loginAuthenticationFilter;
    }


}
