package com.tianzhu.identity.uaa.appconfig.resourceserver;

import com.tianzhu.identity.uaa.authentication.manager.LoginAuthenticationManager;
import com.tianzhu.identity.uaa.oauth.UaaTokenServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;

@Order(0)
//@Configuration
//@EnableResourceServer
public class OauthResourceAuthenticationFilter extends ResourceServerConfigurerAdapter {

    @Autowired
    @Qualifier("loginAuthenticationMgr")
    LoginAuthenticationManager loginAuthenticationMgr;

    @Autowired
    @Qualifier("loginAuthenticateRequestMatcher")
    RequestMatcher loginAuthenticateRequestMatcher;

    @Autowired
    @Qualifier("loginAuthorizeRequestMatcher")
    RequestMatcher loginAuthorizeRequestMatcher;

    @Autowired
    @Qualifier("loginAuthorizeRequestMatcherOld")
    RequestMatcher loginAuthorizeRequestMatcherOld;

    @Autowired
    @Qualifier("loginTokenRequestMatcher")
    RequestMatcher loginTokenRequestMatcher;

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
    @Qualifier("loginClientParameterAuthenticationFilter")
    Filter loginClientParameterAuthenticationFilter;

    @Autowired
    @Qualifier("loginServerTokenEndpointAuthenticationFilter")
    Filter loginServerTokenEndpointAuthenticationFilter;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    AccessDeniedHandler oauthAccessDeniedHandler;

    @Autowired
    @Qualifier("tokenServices")
    UaaTokenServices tokenServices;

    @Autowired
    @Qualifier("oauthAuthenticationEntryPoint")
    OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;


    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.authenticationManager(loginAuthenticationMgr).accessDeniedHandler(oauthAccessDeniedHandler).tokenServices(tokenServices).resourceId("oauth").authenticationEntryPoint(oauthAuthenticationEntryPoint);

    }


    @Override
    public void configure(HttpSecurity http) throws Exception {


        http.requestMatcher(loginAuthenticateRequestMatcher).
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").fullyAuthenticated()
                .and()//.addFilterAt(oauthResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class).addFilterAfter(oauthLoginScopeAuthenticatingFilter,AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();

        http.requestMatcher(loginAuthorizeRequestMatcher).
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").fullyAuthenticated()
                .and()
                .addFilterAt(backwardsCompatibleScopeParameter, ChannelProcessingFilter.class)
                .addFilterAfter(oauthLoginScopeAuthenticatingFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterAt(loginAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();

        http.requestMatcher(loginTokenRequestMatcher).
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").fullyAuthenticated()
                .and()
                .addFilterAt(backwardsCompatibleScopeParameter, ChannelProcessingFilter.class)
                //.addFilterAt(oauthResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterAfter(oauthLoginScopeAuthenticatingFilter,AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterAt(loginClientParameterAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAt(loginServerTokenEndpointAuthenticationFilter, BasicAuthenticationFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();


        http.requestMatcher(loginAuthorizeRequestMatcherOld).
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").fullyAuthenticated()
                .and()
                .addFilterAt(backwardsCompatibleScopeParameter, ChannelProcessingFilter.class)
                //.addFilterAt(oauthResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterAt(loginAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();


        http.requestMatcher(loginAuthorizeRequestMatcherOld).
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").fullyAuthenticated()
                .and()
                .addFilterAt(backwardsCompatibleScopeParameter, ChannelProcessingFilter.class)
                //.addFilterAt(oauthResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterAt(loginAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();

        http.antMatcher("/email_*").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").access("scope=oauth.login")
                .and()//.addFilterAt(oauthResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();
    }
}
