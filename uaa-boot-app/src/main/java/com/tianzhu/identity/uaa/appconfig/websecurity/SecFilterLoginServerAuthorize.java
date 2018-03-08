package com.tianzhu.identity.uaa.appconfig.websecurity;


import com.tianzhu.identity.uaa.authentication.manager.LoginAuthenticationManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;

@Configuration
@Order(12)
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class SecFilterLoginServerAuthorize extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("loginAuthenticationMgr")
    LoginAuthenticationManager loginAuthenticationMgr;

    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return loginAuthenticationMgr;
    }

    @Autowired
    @Qualifier("loginAuthorizeRequestMatcher")
    RequestMatcher loginAuthorizeRequestMatcher;

    @Autowired
    @Qualifier("oauthAuthenticationEntryPoint")
    AuthenticationEntryPoint oauthAuthenticationEntryPoint;

    @Autowired
    @Qualifier("oauthResourceAuthenticationFilter")
    Filter oauthResourceAuthenticationFilter;

    @Autowired
    @Qualifier("oauthLoginScopeAuthenticatingFilter")
    Filter oauthLoginScopeAuthenticatingFilter;

    @Autowired
    @Qualifier("loginAuthenticationFilter")
    Filter loginAuthenticationFilter;

    @Autowired
    @Qualifier("backwardsCompatibleScopeParameter")
    Filter backwardsCompatibleScopeParameter;


    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    AccessDeniedHandler oauthAccessDeniedHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {


        http.requestMatcher(loginAuthorizeRequestMatcher).
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").fullyAuthenticated()
                .and()
                .addFilterAt(backwardsCompatibleScopeParameter, ChannelProcessingFilter.class)
                .addFilterAt(oauthResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterAfter(oauthLoginScopeAuthenticatingFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterAt(loginAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();
    }

}
