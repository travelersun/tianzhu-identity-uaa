package com.tianzhu.identity.uaa.appconfig.resourceserver;

import com.tianzhu.identity.uaa.oauth.UaaTokenServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

@Configuration
@EnableResourceServer
public class ApprovalsResourceAuthenticationFilter extends ResourceServerConfigurerAdapter {


    @Autowired
    @Qualifier("tokenServices")
    UaaTokenServices tokenServices;

    @Autowired
    @Qualifier("oauthAuthenticationEntryPoint")
    OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    AccessDeniedHandler oauthAccessDeniedHandler;


    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {

        resources.tokenServices(tokenServices).resourceId("oauth").authenticationEntryPoint(oauthAuthenticationEntryPoint);

    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/approvals/**").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").access("scope=oauth.approvals")
                //.and().addFilterAt(approvalsResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .and()
                .exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable();
        //http.authorizeRequests().anyRequest().authenticated();

        /*AuthenticationManager oauthAuthenticationManager = oauthAuthenticationManager(http);
        resourcesServerFilter = new OAuth2AuthenticationProcessingFilter();
        resourcesServerFilter.setAuthenticationEntryPoint(authenticationEntryPoint);
        resourcesServerFilter.setAuthenticationManager(oauthAuthenticationManager);
        if (eventPublisher != null) {
            resourcesServerFilter.setAuthenticationEventPublisher(eventPublisher);
        }
        if (tokenExtractor != null) {
            resourcesServerFilter.setTokenExtractor(tokenExtractor);
        }
        resourcesServerFilter = postProcess(resourcesServerFilter);
        resourcesServerFilter.setStateless(stateless);

        // @formatter:off
        http
                .authorizeRequests().expressionHandler(expressionHandler)
                .and()
                .addFilterBefore(resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler)
                .authenticationEntryPoint(authenticationEntryPoint);
        // @formatter:on*/

        //http.authorizeRequests().accessDecisionManager()

    }





}
