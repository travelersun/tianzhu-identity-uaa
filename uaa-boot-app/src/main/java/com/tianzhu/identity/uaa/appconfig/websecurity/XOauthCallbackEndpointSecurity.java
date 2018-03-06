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
@Order(25)
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class XOauthCallbackEndpointSecurity extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("loginEntryPoint")
    AuthenticationEntryPoint loginEntryPoint;

    @Autowired
    @Qualifier("xOauthCallbackAuthenticationFilter")
    Filter xOauthCallbackAuthenticationFilter;

    @Autowired
    @Qualifier("xOauthCallbackRequestMatcher")
    RequestMatcher xOauthCallbackRequestMatcher;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatcher(xOauthCallbackRequestMatcher).
                //sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(loginEntryPoint).and()
                .authorizeRequests().antMatchers("**").fullyAuthenticated()
                .and().addFilterAt(xOauthCallbackAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .anonymous().disable().csrf().disable();
    }


}
