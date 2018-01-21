package com.tianzhu.identity.uaa.appconfig.websecurity;


import com.tianzhu.identity.uaa.authentication.manager.LoginAuthenticationManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class SecFilterLoginServerPasswordEndpoints extends WebSecurityConfigurerAdapter {

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
        http.requestMatchers().antMatchers("/password_*").and().
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").access("#oauth2.hasScope('oauth.login') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .and()
                .addFilterAt(oauthWithoutResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();
        http.authorizeRequests().expressionHandler(oauthWebExpressionHandler);
    }


    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return emptyAuthenticationManager;
    }

}
