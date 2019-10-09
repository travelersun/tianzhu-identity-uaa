package com.tianzhu.identity.uaa.appconfig.filter;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;

@Configuration
public class OauthResouresServerFilterConfig {


    @Bean
    public FilterRegistrationBean unregistRSF1(@Qualifier("approvalsResourceAuthenticationFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public FilterRegistrationBean unregistRSF2(@Qualifier("clientResourceAuthenticationFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public FilterRegistrationBean unregistRSF3(@Qualifier("idsResourceAuthenticationFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public FilterRegistrationBean unregistRSF4(@Qualifier("oauthResourceAuthenticationFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public FilterRegistrationBean unregistRSF5(@Qualifier("oauthWithoutResourceAuthenticationFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public FilterRegistrationBean unregistRSF6(@Qualifier("openidResourceAuthenticationFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public FilterRegistrationBean unregistRSF7(@Qualifier("passwordResourceAuthenticationFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public FilterRegistrationBean unregistRSF8(@Qualifier("resourceAgnosticAuthenticationFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public FilterRegistrationBean unregistRSF9(@Qualifier("scimResourceAuthenticationFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }
}
