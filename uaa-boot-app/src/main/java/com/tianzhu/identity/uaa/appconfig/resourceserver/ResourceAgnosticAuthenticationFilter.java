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
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;


@Order(30)
//@Configuration
//@EnableResourceServer
public class ResourceAgnosticAuthenticationFilter extends ResourceServerConfigurerAdapter {

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
    @Qualifier("backwardsCompatibleScopeParameter")
    Filter backwardsCompatibleScopeParameter;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    AccessDeniedHandler oauthAccessDeniedHandler;

    @Autowired
    @Qualifier("oauthWebExpressionHandler")
    SecurityExpressionHandler oauthWebExpressionHandler;

    @Autowired
    @Qualifier("oauthTokenApiRequestMatcher")
    RequestMatcher oauthTokenApiRequestMatcher;

    @Autowired
    @Qualifier("oauthAuthorizeApiRequestMatcher")
    RequestMatcher oauthAuthorizeApiRequestMatcher;


    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {

        resources.authenticationManager(emptyAuthenticationManager).accessDeniedHandler(oauthAccessDeniedHandler).expressionHandler(oauthWebExpressionHandler).tokenServices(tokenServices).authenticationEntryPoint(oauthAuthenticationEntryPoint);


    }

    @Override
    public void configure(HttpSecurity http) throws Exception {



        http.antMatcher("/oauth/token/revoke/**").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests()
                .antMatchers("/oauth/token/revoke/client/**").access("#oauth2.hasScope('tokens.revoke')")
                .antMatchers("/oauth/token/revoke/user/**/client/**").access("#oauth2.hasScope('uaa.admin') or #oauth2.hasScope('tokens.revoke') or (@self.isUserTokenRevocationForSelf(request, 4) and @self.isClientTokenRevocationForSelf(request, 6))")
                .antMatchers("/oauth/token/revoke/user/**").access("#oauth2.hasScope('uaa.admin') or (#oauth2.hasScope('tokens.revoke') and @self.isUserTokenRevocationForSelf(request, 4))")
                .antMatchers(HttpMethod.DELETE,"/oauth/token/revoke/**").access("#oauth2.hasScope('tokens.revoke') or @self.isTokenRevocationForSelf(request, 3)")
                .antMatchers("/**").denyAll()
                .and()//.addFilterAt(oauthResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);


        http.antMatcher("/oauth/token/list/**").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET,"/oauth/token/list/user/**").access("#oauth2.hasScope('tokens.list')")
                .antMatchers(HttpMethod.GET,"/oauth/token/list/client/**").access("#oauth2.hasScope('tokens.list')")
                .antMatchers("/**").denyAll()
                .and()//.addFilterAt(oauthResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);


        http.requestMatcher(oauthTokenApiRequestMatcher).
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests()
                .antMatchers("/**").access("#oauth2.hasScope('uaa.user')")
                .and()
                .addFilterAt(backwardsCompatibleScopeParameter, ChannelProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);



        http.requestMatcher(oauthAuthorizeApiRequestMatcher).
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests()
                .antMatchers("/**").access("#oauth2.hasScope('uaa.user')")
                .and()
                .addFilterAt(backwardsCompatibleScopeParameter, ChannelProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);



        http.antMatcher("/Groups/**").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests()
                .antMatchers("/Groups/zones").access("#oauth2.hasScopeInAuthZone('scim.zones')")
                .antMatchers("/Groups/zones/**").access("#oauth2.hasScopeInAuthZone('scim.zones')")
                .antMatchers(HttpMethod.GET,"/Groups/External").access("#oauth2.hasScope('scim.read') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.POST,"/Groups/External").access("#oauth2.hasScope('scim.read') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.DELETE,"/Groups/External/**").access("#oauth2.hasScope('scim.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.DELETE,"/Groups/**").access("#oauth2.hasScope('scim.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.PUT,"/Groups/**").access("#oauth2.hasAnyScope('scim.write', 'groups.update') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.POST,"/Groups/**").access("#oauth2.hasAnyScope('scim.write', 'groups.update') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.GET,"/Groups/**").access("#oauth2.hasScope('scim.read') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.PATCH,"/Groups/**").access("#oauth2.hasAnyScope('scim.write', 'groups.update') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.POST,"/Groups").access("#oauth2.hasScope('scim.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers("/**").denyAll()
                .and()//.addFilterAt(resourceAgnosticAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);


        http.antMatcher("/Users/**").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET,"/Users/*/verify-link").access("#oauth2.hasAnyScope('scim.create') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.GET,"/Users/*/verify").access("#oauth2.hasAnyScope('scim.write','scim.create') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.PATCH,"/Users/*/status").access("#oauth2.hasAnyScope('scim.write','uaa.account_status.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.GET,"/Users/**").access("#oauth2.hasAnyScope('scim.read') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin') or @self.isUserSelf(request,1)")
                .antMatchers(HttpMethod.DELETE,"/Users/*").access("#oauth2.hasAnyScope('scim.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.PUT,"/Users/*").access("#oauth2.hasAnyScope('scim.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin') or @self.isUserSelf(request,1)")
                .antMatchers(HttpMethod.PATCH,"/Users/*").access("#oauth2.hasAnyScope('scim.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin') or @self.isUserSelf(request,1)")
                .antMatchers(HttpMethod.POST,"/Users").access("#oauth2.hasAnyScope('scim.write','scim.create') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers("/**").denyAll()
                .and()//.addFilterAt(resourceAgnosticAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);
        //http.authorizeRequests().expressionHandler(oauthWebExpressionHandler);


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
                .and()//.addFilterAt(resourceAgnosticAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);
        //http.authorizeRequests().expressionHandler(oauthWebExpressionHandler);



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
                .and()//.addFilterAt(resourceAgnosticAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);


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
                .and()//.addFilterBefore(resourceAgnosticAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);



        http.antMatcher("/saml/service-providers/**").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST,"/**").access("#oauth2.hasScope('sps.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.PUT,"/**").access("#oauth2.hasScope('sps.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.GET,"/**").access("#oauth2.hasScope('sps.read') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers(HttpMethod.DELETE,"/**").access("#oauth2.hasScope('sps.write') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .antMatchers("/**").denyAll()
                .and()//.addFilterBefore(resourceAgnosticAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);


        http.antMatcher("/Codes/**").
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers("/**").access("#oauth2.hasAnyScope('oauth.login')")
                .and()//.addFilterAt(resourceAgnosticAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .anonymous().disable().exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);

        http.antMatcher("/invite_users/**").
                exceptionHandling().authenticationEntryPoint(oauthAuthenticationEntryPoint).and()
                .authorizeRequests().antMatchers(HttpMethod.POST,"/**").access("#oauth2.hasAnyScope('scim.invite') or #oauth2.hasScopeInAuthZone('zones.{zone.id}.admin')")
                .and()
                .authorizeRequests().antMatchers("**").denyAll()
                .and()
                //.addFilterAt(resourceAgnosticAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().disable().authorizeRequests().expressionHandler(oauthWebExpressionHandler);
    }
}
