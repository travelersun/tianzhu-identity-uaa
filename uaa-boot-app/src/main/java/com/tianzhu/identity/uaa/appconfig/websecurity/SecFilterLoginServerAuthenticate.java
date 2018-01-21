package com.tianzhu.identity.uaa.appconfig.websecurity;


import com.tianzhu.identity.uaa.authentication.manager.LoginAuthenticationManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class SecFilterLoginServerAuthenticate extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("loginAuthenticationMgr")
    LoginAuthenticationManager loginAuthenticationMgr;

    @Autowired
    @Qualifier("loginAuthenticateRequestMatcher")
    RequestMatcher loginAuthenticateRequestMatcher;

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
    @Qualifier("oauthAccessDeniedHandler")
    AccessDeniedHandler oauthAccessDeniedHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatcher(loginAuthenticateRequestMatcher).
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").fullyAuthenticated()
                .and().addFilterAt(oauthResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class).addFilterAfter(oauthLoginScopeAuthenticatingFilter,AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();
    }


    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return loginAuthenticationMgr;
    }

}
