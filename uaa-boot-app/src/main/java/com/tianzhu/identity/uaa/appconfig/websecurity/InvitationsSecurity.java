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
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import javax.servlet.Filter;
@Order(60)
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class InvitationsSecurity extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("emptyAuthenticationManager")
    AuthenticationManager emptyAuthenticationManager;

    @Autowired
    @Qualifier("loginEntryPoint")
    AuthenticationEntryPoint loginEntryPoint;

    @Autowired
    @Qualifier("acceptInvitationSecurityContextPersistenceFilter")
    Filter acceptInvitationSecurityContextPersistenceFilter;

    @Autowired
    @Qualifier("loginEntryPoint")
    AccessDeniedHandler oauthAccessDeniedHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/invitations/**").exceptionHandling().authenticationEntryPoint(loginEntryPoint).and()
                .authorizeRequests().antMatchers(HttpMethod.GET,"/invitations/accept").access("isFullyAuthenticated() or isAnonymous()")
                .and()
                .authorizeRequests().antMatchers(HttpMethod.POST,"/invitations/accept.do").access("hasAuthority('uaa.invited')")
                .and()
                .authorizeRequests().antMatchers(HttpMethod.POST,"/invitations/accept_enterprise.do").access("hasAuthority('uaa.invited')")
                .and()
                .authorizeRequests().antMatchers("/**").denyAll()
                .and()
                .addFilterBefore(acceptInvitationSecurityContextPersistenceFilter, ChannelProcessingFilter.class)
                .exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler);
    }


    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return emptyAuthenticationManager;
    }

}
