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
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;

@Configuration
@Order(19)
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class TokenEndpointSecurityForPasscodes extends WebSecurityConfigurerAdapter {

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
    @Qualifier("backwardsCompatibleScopeParameter")
    Filter backwardsCompatibleScopeParameter;

    @Autowired
    @Qualifier("clientParameterAuthenticationFilter")
    Filter clientParameterAuthenticationFilter;

    @Autowired
    @Qualifier("clientAuthenticationFilter")
    Filter clientAuthenticationFilter;

    @Autowired
    @Qualifier("passcodeAuthenticationFilter")
    Filter passcodeAuthenticationFilter;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    AccessDeniedHandler oauthAccessDeniedHandler;

    @Autowired
    @Qualifier("passcodeTokenMatcher")
    RequestMatcher passcodeTokenMatcher;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatcher(passcodeTokenMatcher).
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(basicAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").fullyAuthenticated()
                .and()
                .addFilterAt(backwardsCompatibleScopeParameter, ChannelProcessingFilter.class)
                .addFilterBefore(clientParameterAuthenticationFilter, BasicAuthenticationFilter.class)
                .addFilterAt(clientAuthenticationFilter, BasicAuthenticationFilter.class)
                .addFilterAfter(passcodeAuthenticationFilter, BasicAuthenticationFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();
    }


}
