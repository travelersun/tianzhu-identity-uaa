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
@Order(38)
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class ClientAdminSecurity extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("emptyAuthenticationManager")
    AuthenticationManager emptyAuthenticationManager;

    @Autowired
    @Qualifier("oauthAuthenticationEntryPoint")
    AuthenticationEntryPoint oauthAuthenticationEntryPoint;

    @Autowired
    @Qualifier("oauthWithoutResourceAuthenticationFilter")
    Filter oauthWithoutResourceAuthenticationFilter;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    AccessDeniedHandler oauthAccessDeniedHandler;

    @Autowired
    @Qualifier("oauthWebExpressionHandler")
    SecurityExpressionHandler oauthWebExpressionHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/oauth/clients/**").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET,"/oauth/clients/**/meta").fullyAuthenticated()
                .antMatchers(HttpMethod.DELETE,"/**").access("#oauth2.hasAnyScope('clients.write','clients.admin') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.POST,"/**").access("#oauth2.hasAnyScope('clients.write','clients.admin') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.PUT,"/**").access("#oauth2.hasAnyScope('clients.write','clients.admin') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.GET,"/**").access("#oauth2.hasAnyScope('clients.read','clients.admin') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers("/**").denyAll()
                .and().addFilterAt(oauthWithoutResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);
    }


    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return emptyAuthenticationManager;
    }

}
