package com.tianzhu.identity.uaa.appconfig.websecurity;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class UiSecurity extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("uiRequestMatcher")
    RequestMatcher uiRequestMatcher;

    @Autowired
    @Qualifier("uiCookeCsrfRequestMatcher")
    RequestMatcher uiCookeCsrfRequestMatcher;

    @Autowired
    @Qualifier("zoneAwareAuthzAuthenticationManager")
    AuthenticationManager zoneAwareAuthzAuthenticationManager;

    @Autowired
    @Qualifier("clientRedirectStateCache")
    Filter clientRedirectStateCache;

    @Autowired
    @Qualifier("logoutFilter")
    Filter logoutFilter;

    @Autowired
    @Qualifier("samlLogoutFilter")
    Filter samlLogoutFilter;

    @Autowired
    @Qualifier("loginCookieCsrfRepository")
    CsrfTokenRepository loginCookieCsrfRepository;

    @Autowired
    @Qualifier("accountSavingAuthenticationSuccessHandler")
    AuthenticationSuccessHandler accountSavingAuthenticationSuccessHandler;

    @Autowired
    @Qualifier("uaaAuthenticationFailureHandler")
    AuthenticationFailureHandler uaaAuthenticationFailureHandler;

    @Autowired
    @Qualifier("authenticationDetailsSource")
    AuthenticationDetailsSource<HttpServletRequest, ?>  authenticationDetailsSource;

    @Autowired
    @Qualifier("clientRedirectStateCache")
    RequestCache requestCache;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatcher(uiRequestMatcher).requestCache().requestCache(requestCache).and()
                .authorizeRequests().antMatchers("/login**").anonymous()
                .and()
                .authorizeRequests().antMatchers("/login/idp_discovery").anonymous()
                .and()
                .authorizeRequests().antMatchers("/**").fullyAuthenticated()
                .and()
                .formLogin().loginPage("/login").usernameParameter("username").passwordParameter("password").loginProcessingUrl("/login.do").successForwardUrl("/")
                .successHandler(accountSavingAuthenticationSuccessHandler).failureHandler(uaaAuthenticationFailureHandler).authenticationDetailsSource(authenticationDetailsSource)
                .and()
                .addFilterBefore(clientRedirectStateCache, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(logoutFilter, LogoutFilter.class)
                .addFilterBefore(samlLogoutFilter, LogoutFilter.class)
                .exceptionHandling().accessDeniedPage("/login?error=invalid_login_request").and()
                .csrf().csrfTokenRepository(loginCookieCsrfRepository).requireCsrfProtectionMatcher(uiCookeCsrfRequestMatcher);
    }


    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return zoneAwareAuthzAuthenticationManager;
    }

}
