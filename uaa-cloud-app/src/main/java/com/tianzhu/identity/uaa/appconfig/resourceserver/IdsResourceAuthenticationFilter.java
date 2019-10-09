package com.tianzhu.identity.uaa.appconfig.resourceserver;

import com.tianzhu.identity.uaa.oauth.UaaTokenServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

@Order(40)
//@Configuration
//@EnableResourceServer
public class IdsResourceAuthenticationFilter extends ResourceServerConfigurerAdapter {

    @Autowired
    @Qualifier("emptyAuthenticationManager")
    AuthenticationManager emptyAuthenticationManager;

    @Autowired
    @Qualifier("tokenServices")
    UaaTokenServices tokenServices;

    @Autowired
    @Qualifier("oauthAuthenticationEntryPoint")
    OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    AccessDeniedHandler oauthAccessDeniedHandler;

    @Autowired
    @Qualifier("accessDecisionManager")
    AccessDecisionManager accessDecisionManager;


    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {

        resources.authenticationManager(emptyAuthenticationManager).accessDeniedHandler(oauthAccessDeniedHandler).tokenServices(tokenServices).authenticationEntryPoint(oauthAuthenticationEntryPoint);

    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/ids/Users*").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().accessDecisionManager(accessDecisionManager).antMatchers("/**").access("scope=scim.userids")
                .and()
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();

    }
}
