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
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import javax.servlet.Filter;

@Configuration
@Order(21)
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class TokenEndpointSecurity extends WebSecurityConfigurerAdapter {

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
    @Qualifier("backwardsCompatibleScopeParameter")
    Filter backwardsCompatibleScopeParameter;

    @Autowired
    @Qualifier("clientAuthenticationFilter")
    Filter clientAuthenticationFilter;

    @Autowired
    @Qualifier("clientParameterAuthenticationFilter")
    Filter clientParameterAuthenticationFilter;

    @Autowired
    @Qualifier("tokenEndpointAuthenticationFilter")
    Filter tokenEndpointAuthenticationFilter;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    AccessDeniedHandler oauthAccessDeniedHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/oauth/token/**").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(basicAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").fullyAuthenticated()
                .and()
                .addFilterAt(backwardsCompatibleScopeParameter, ChannelProcessingFilter.class)
                .addFilterAt(clientAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(clientParameterAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(tokenEndpointAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();
    }


    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return clientAuthenticationManager;
    }

}
