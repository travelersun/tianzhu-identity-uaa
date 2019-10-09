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
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.Filter;
@Order(41)
@Configuration
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class ClientInfoSecurity extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("clientAuthenticationManager")
    AuthenticationManager clientAuthenticationManager;

    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return clientAuthenticationManager;
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
        http.antMatcher("/clientinfo").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(basicAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").fullyAuthenticated()
                .and().addFilterAt(clientAuthenticationFilter, BasicAuthenticationFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler);
    }

}
