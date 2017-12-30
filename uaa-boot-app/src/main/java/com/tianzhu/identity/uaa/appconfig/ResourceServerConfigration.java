package com.tianzhu.identity.uaa.appconfig;

import com.tianzhu.identity.uaa.oauth.UaaTokenServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;

@Configuration
@EnableResourceServer
//@ImportResource({"classpath:spring/resource-server.xml"})
public class ResourceServerConfigration extends ResourceServerConfigurerAdapter{


    @Autowired
    @Qualifier("tokenServices")
    UaaTokenServices tokenServices;

    @Autowired
    @Qualifier("oauthAuthenticationEntryPoint")
    OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;


    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.tokenServices(tokenServices).resourceId("oauth").authenticationEntryPoint(oauthAuthenticationEntryPoint);
        resources.tokenServices(tokenServices).authenticationEntryPoint(oauthAuthenticationEntryPoint);
        resources.tokenServices(tokenServices).resourceId("password").authenticationEntryPoint(oauthAuthenticationEntryPoint);
        resources.tokenServices(tokenServices).resourceId("scim").authenticationEntryPoint(oauthAuthenticationEntryPoint);
        resources.tokenServices(tokenServices).authenticationEntryPoint(oauthAuthenticationEntryPoint);
        resources.tokenServices(tokenServices).authenticationEntryPoint(oauthAuthenticationEntryPoint);
        resources.tokenServices(tokenServices).resourceId("oauth").authenticationEntryPoint(oauthAuthenticationEntryPoint);
        resources.tokenServices(tokenServices).resourceId("clients").authenticationEntryPoint(oauthAuthenticationEntryPoint);
        resources.tokenServices(tokenServices).resourceId("openid").authenticationEntryPoint(oauthAuthenticationEntryPoint);

    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

        http.exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and().authorizeRequests().anyRequest().authenticated();
    }
}
