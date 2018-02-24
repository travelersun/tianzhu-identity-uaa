package com.tianzhu.identity.uaa.appconfig.resourceserver;

import com.tianzhu.identity.uaa.oauth.UaaTokenServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

@Order(5)
@Configuration
@EnableResourceServer
public class OauthWithoutResourceAuthenticationFilter extends ResourceServerConfigurerAdapter {

    @Autowired
    @Qualifier("emptyAuthenticationManager")
    AuthenticationManager emptyAuthenticationManager;

    @Autowired
    @Qualifier("tokenServices")
    UaaTokenServices tokenServices;

    @Autowired
    @Qualifier("oauthAuthenticationEntryPoint")
    OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    AccessDeniedHandler oauthAccessDeniedHandler;

    @Autowired
    @Qualifier("oauthWebExpressionHandler")
    SecurityExpressionHandler oauthWebExpressionHandler;


    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {

        resources.authenticationManager(emptyAuthenticationManager).accessDeniedHandler(oauthAccessDeniedHandler).expressionHandler(oauthWebExpressionHandler).tokenServices(tokenServices).authenticationEntryPoint(oauthAuthenticationEntryPoint);

    }

    @Override
    public void configure(HttpSecurity http) throws Exception {


        http.requestMatchers().antMatchers("/password_*").and().
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").access("#oauth2.hasScope('oauth.login') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .and()
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);

        http.antMatcher("/oauth/clients/*/secret").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/oauth/clients/*/secret").access("#oauth2.hasAnyScope('clients.secret', 'clients.admin') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .and()//.addFilterAt(oauthWithoutResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);


        http.antMatcher("/oauth/clients/tx/**").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests()
                .antMatchers(HttpMethod.DELETE,"/**").access("#oauth2.hasAnyScope('clients.admin') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.POST,"/**").access("#oauth2.hasAnyScope('clients.admin') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.PUT,"/**").access("#oauth2.hasAnyScope('clients.admin') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .and()//.addFilterBefore(oauthWithoutResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);


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
                .and()//.addFilterAt(oauthWithoutResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);

    }
}
