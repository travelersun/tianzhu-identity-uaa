package com.tianzhu.identity.uaa.appconfig.websecurity;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
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

import javax.servlet.Filter;

@Configuration
@Order(18)
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class TokenListFilter extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("emptyAuthenticationManager")
    AuthenticationManager emptyAuthenticationManager;

    @Autowired
    @Qualifier("oauthAuthenticationEntryPoint")
    AuthenticationEntryPoint oauthAuthenticationEntryPoint;

    @Autowired
    @Qualifier("resourceAgnosticAuthenticationFilter")
    Filter resourceAgnosticAuthenticationFilter;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    AccessDeniedHandler oauthAccessDeniedHandler;

    @Autowired
    @Qualifier("oauthWebExpressionHandler")
    SecurityExpressionHandler oauthWebExpressionHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/oauth/token/list/**").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET,"/oauth/token/list/user/**").access("#oauth2.hasScope('tokens.list')")
                .antMatchers(HttpMethod.GET,"/oauth/token/list/client/**").access("#oauth2.hasScope('tokens.list')")
                .antMatchers("/**").denyAll()
                .and().addFilterAt(resourceAgnosticAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);

    }


    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return emptyAuthenticationManager;
    }

}
