package com.tianzhu.identity.uaa.appconfig.websecurity;


import com.tianzhu.identity.uaa.authentication.manager.LoginAuthenticationManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;

@Configuration
@Order(16)
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class SecFilterLoginServerEmailEndpoints extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("emptyAuthenticationManager")
    AuthenticationManager emptyAuthenticationManager;

    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return emptyAuthenticationManager;
    }

    @Autowired
    @Qualifier("oauthAuthenticationEntryPoint")
    AuthenticationEntryPoint oauthAuthenticationEntryPoint;

    @Autowired
    @Qualifier("oauthResourceAuthenticationFilter")
    Filter oauthResourceAuthenticationFilter;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    AccessDeniedHandler oauthAccessDeniedHandler;


    @Autowired
    @Qualifier("accessDecisionManager")
    AccessDecisionManager accessDecisionManager;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/email_*").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().accessDecisionManager(accessDecisionManager).antMatchers("/**").access("scope=oauth.login")
                .and().addFilterAt(oauthResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();
    }


}
