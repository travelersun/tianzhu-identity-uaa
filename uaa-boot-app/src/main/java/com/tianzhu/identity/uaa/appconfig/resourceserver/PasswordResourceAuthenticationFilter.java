package com.tianzhu.identity.uaa.appconfig.resourceserver;

import com.tianzhu.identity.uaa.oauth.UaaTokenServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;

@Configuration
@EnableResourceServer
public class PasswordResourceAuthenticationFilter extends ResourceServerConfigurerAdapter {

    @Autowired
    @Qualifier("tokenServices")
    UaaTokenServices tokenServices;

    @Autowired
    @Qualifier("oauthAuthenticationEntryPoint")
    OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;


    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {

        resources.tokenServices(tokenServices).resourceId("password").authenticationEntryPoint(oauthAuthenticationEntryPoint);

    }

}
