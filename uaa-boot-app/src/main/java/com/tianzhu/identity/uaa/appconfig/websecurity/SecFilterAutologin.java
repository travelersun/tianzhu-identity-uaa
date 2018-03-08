package com.tianzhu.identity.uaa.appconfig.websecurity;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.Filter;
@Order(46)
@Configuration
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class SecFilterAutologin extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("emptyAuthenticationManager")
    AuthenticationManager emptyAuthenticationManager;

    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return emptyAuthenticationManager;
    }

    @Autowired
    @Qualifier("basicAuthenticationEntryPoint")
    AuthenticationEntryPoint basicAuthenticationEntryPoint;

    @Autowired
    @Qualifier("clientAuthenticationFilter")
    Filter clientAuthenticationFilter;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    AccessDeniedHandler oauthAccessDeniedHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/autologin").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(basicAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers(HttpMethod.POST,"/**").fullyAuthenticated()
                .and().addFilterAt(clientAuthenticationFilter, BasicAuthenticationFilter.class)
                .anonymous().disable().csrf().disable();
    }


}
