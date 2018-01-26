package com.tianzhu.identity.uaa.appconfig.websecurity;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
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
@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class IdentityZoneSecurity extends WebSecurityConfigurerAdapter {

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
        http.antMatcher("/identity-zones/**").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET,"/identity-zones").access("#oauth2.hasScopeInAuthZone('zones.read') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin') or #oauth2.hasScope('zones.write')")
                .antMatchers(HttpMethod.GET,"/identity-zones/*").access("#oauth2.hasScopeInAuthZone('zones.read') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.read') or #oauth2.hasScope('zones.write')")
                .antMatchers(HttpMethod.POST,"/identity-zones/*/clients").access("#oauth2.hasScopeInAuthZone('zones.write')")
                .antMatchers(HttpMethod.DELETE,"/identity-zones/*/clients/*").access("#oauth2.hasScopeInAuthZone('zones.write')")
                .antMatchers(HttpMethod.POST,"/**").access("#oauth2.hasScopeInAuthZone('zones.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.PUT,"/**").access("#oauth2.hasScopeInAuthZone('zones.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin') or #oauth2.hasScope('zones.write')")
                .antMatchers(HttpMethod.DELETE,"/**").access("#oauth2.hasScopeInAuthZone('zones.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers("/**").denyAll()
                .and().addFilterAt(resourceAgnosticAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();
        http.authorizeRequests().expressionHandler(oauthWebExpressionHandler);
    }


    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return emptyAuthenticationManager;
    }

}
