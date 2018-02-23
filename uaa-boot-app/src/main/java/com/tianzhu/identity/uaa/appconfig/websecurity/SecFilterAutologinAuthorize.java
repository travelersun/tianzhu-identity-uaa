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
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;
@Order(20)
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class SecFilterAutologinAuthorize extends WebSecurityConfigurerAdapter {


    @Autowired
    @Qualifier("autologinAuthorizeRequestMatcher")
    RequestMatcher autologinAuthorizeRequestMatcher;

    @Autowired
    @Qualifier("loginEntryPoint")
    AuthenticationEntryPoint loginEntryPoint;

    @Autowired
    @Qualifier("autologinAuthenticationFilter")
    Filter autologinAuthenticationFilter;


    @Autowired
    @Qualifier("loginCookieCsrfRepository")
    CsrfTokenRepository csrfTokenRepository;


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatcher(autologinAuthorizeRequestMatcher).
                exceptionHandling().authenticationEntryPoint(loginEntryPoint).and()
                .authorizeRequests()
                .antMatchers("/**").access("scope=oauth.login")
                .and().addFilterAt(autologinAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .anonymous().disable().csrf().csrfTokenRepository(csrfTokenRepository);
    }

}
