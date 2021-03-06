package com.tianzhu.identity.uaa.appconfig.websecurity;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;

import javax.servlet.Filter;
@Order(120)
@Configuration
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class ForcePasswordChangeSecurity extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("loginEntryPoint")
    AuthenticationEntryPoint loginEntryPoint;


    @Autowired
    @Qualifier("loginEntryPoint")
    AccessDeniedHandler oauthAccessDeniedHandler;

    @Autowired
    @Qualifier("loginCookieCsrfRepository")
    CsrfTokenRepository loginCookieCsrfRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/force_password_change**").
                exceptionHandling().authenticationEntryPoint(loginEntryPoint).and()
                .authorizeRequests().antMatchers("/**").anonymous()
                .and()
                .exceptionHandling().accessDeniedHandler(oauthAccessDeniedHandler).and().csrf().csrfTokenRepository(loginCookieCsrfRepository);
    }


}
