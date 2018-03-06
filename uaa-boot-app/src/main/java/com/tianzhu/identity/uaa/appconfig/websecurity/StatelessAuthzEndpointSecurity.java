package com.tianzhu.identity.uaa.appconfig.websecurity;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;

@Configuration
@Order(22)
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class StatelessAuthzEndpointSecurity extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("zoneAwareAuthzAuthenticationManager")
    AuthenticationManager zoneAwareAuthzAuthenticationManager;

    @Autowired
    @Qualifier("oauthAuthenticationEntryPoint")
    AuthenticationEntryPoint oauthAuthenticationEntryPoint;

    @Autowired
    @Qualifier("backwardsCompatibleScopeParameter")
    Filter backwardsCompatibleScopeParameter;

    @Autowired
    @Qualifier("authzAuthenticationFilter")
    Filter authzAuthenticationFilter;

    @Autowired
    @Qualifier("oauthAuthorizeRequestMatcher")
    RequestMatcher oauthAuthorizeRequestMatcher;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    AccessDeniedHandler oauthAccessDeniedHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatcher(oauthAuthorizeRequestMatcher).
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").fullyAuthenticated()
                .and()
                .addFilterAt(backwardsCompatibleScopeParameter, AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterAt(authzAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();
    }


    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return zoneAwareAuthzAuthenticationManager;
    }

}
