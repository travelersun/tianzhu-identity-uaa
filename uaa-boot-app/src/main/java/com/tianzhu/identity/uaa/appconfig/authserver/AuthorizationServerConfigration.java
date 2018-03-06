package com.tianzhu.identity.uaa.appconfig.authserver;

import com.tianzhu.identity.uaa.authentication.manager.CompositeAuthenticationManager;
import com.tianzhu.identity.uaa.oauth.*;
import com.tianzhu.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;

import javax.annotation.PostConstruct;
import java.util.ArrayList;

//@Configuration
//@EnableAuthorizationServer
public class AuthorizationServerConfigration extends AuthorizationServerConfigurerAdapter{

    @Autowired
    @Qualifier("jdbcClientDetailsService")
    MultitenantJdbcClientDetailsService jdbcClientDetailsService;

    @Autowired
    @Qualifier("tokenServices")
    UaaTokenServices tokenServices;

    @Autowired
    @Qualifier("userManagedApprovalHandler")
    UserManagedAuthzApprovalHandler userManagedApprovalHandler;

    @Autowired
    @Qualifier("authorizationRequestManager")
    UaaAuthorizationRequestManager authorizationRequestManager;

    @Autowired
    @Qualifier("oauth2RequestValidator")
    UaaOauth2RequestValidator oauth2RequestValidator;

    @Autowired
    @Qualifier("authorizationCodeServices")
    UaaTokenStore authorizationCodeServices;

    @Autowired
    @Qualifier("compositeAuthenticationManager")
    CompositeAuthenticationManager compositeAuthenticationManager;

    @Bean
    public CompositeTokenGranter oauth2TokenGranter(){
        return new CompositeTokenGranter(new ArrayList<>());
    }


    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(jdbcClientDetailsService);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenServices(tokenServices);
        endpoints.userApprovalHandler(userManagedApprovalHandler);
        endpoints.requestFactory(authorizationRequestManager);
        endpoints.requestValidator(oauth2RequestValidator);
        endpoints.authorizationCodeServices(authorizationCodeServices);
        endpoints.authenticationManager(compositeAuthenticationManager);
        endpoints.setClientDetailsService(jdbcClientDetailsService);
        //endpoints.pathMapping("/oauth/confirm_access","/oauth/uaa_confirm_access");
        //endpoints.pathMapping("/oauth/error","/oauth/uaa_error");

    }
}
