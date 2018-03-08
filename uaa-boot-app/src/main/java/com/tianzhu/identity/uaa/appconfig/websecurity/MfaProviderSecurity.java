package com.tianzhu.identity.uaa.appconfig.websecurity;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import javax.servlet.Filter;

@Configuration
@Order(31)
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class MfaProviderSecurity extends WebSecurityConfigurerAdapter {

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
        http.antMatcher("/mfa-providers/**").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST,"/mfa-providers").access("#oauth2.hasAnyScope('scim.create') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.GET,"/mfa-providers").access("#oauth2.hasAnyScope('scim.write','scim.create') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.PUT,"/mfa-providers/*").access("#oauth2.hasAnyScope('scim.write','uaa.account_status.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.GET,"/mfa-providers/*").access("#oauth2.hasAnyScope('scim.read') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin') or @self.isUserSelf(request,1)")
                .antMatchers(HttpMethod.DELETE,"/mfa-providers/*").access("#oauth2.hasAnyScope('scim.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers("/**").denyAll()
                .and().addFilterAt(resourceAgnosticAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);
    }


}
