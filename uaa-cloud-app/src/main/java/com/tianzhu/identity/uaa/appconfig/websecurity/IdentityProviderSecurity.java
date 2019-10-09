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
@Order(33)
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class IdentityProviderSecurity extends WebSecurityConfigurerAdapter {

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
        http.antMatcher("/identity-providers/**").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST,"/**").access("#oauth2.hasScope('idps.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.PUT,"/**").access("#oauth2.hasScope('idps.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.PATCH,"/**").access("#oauth2.hasScope('idps.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.DELETE,"/**").access("#oauth2.hasScope('idps.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.GET,"/**").access("#oauth2.hasScope('idps.read') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers("/**").denyAll()
                .and().addFilterBefore(resourceAgnosticAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);
    }


}
