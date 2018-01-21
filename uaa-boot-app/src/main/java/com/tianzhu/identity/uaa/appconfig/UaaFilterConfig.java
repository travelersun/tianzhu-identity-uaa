package com.tianzhu.identity.uaa.appconfig;

import com.tianzhu.identity.uaa.web.BackwardsCompatibleScopeParsingFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.web.filter.DelegatingFilterProxy;

import javax.servlet.Filter;

/**
 * Created by gzcss on 2017/12/13.
 */
@Configuration
//@Order(Ordered.HIGHEST_PRECEDENCE)
public class UaaFilterConfig {

    /*
    @Bean
    @ConditionalOnBean(
            name = {"springSecurityFilterChain"}
    )
    public DelegatingFilterProxyRegistrationBean securityFilterChainRegistration() {
        DelegatingFilterProxyRegistrationBean registration = new DelegatingFilterProxyRegistrationBean("springSecurityFilterChain", new ServletRegistrationBean[0]);
        registration.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER);
        //registration.setDispatcherTypes(this.getDispatcherTypes(securityProperties));
        return registration;
    }*/

    /*
    @Bean
    public FilterRegistrationBean springSecurityFilterChainRegistration() {
        FilterRegistrationBean registration = new FilterRegistrationBean(delegatingFilterProxy());
        registration.addInitParameter("contextAttribute","org.springframework.web.servlet.FrameworkServlet.CONTEXT.spring");
        registration.setName("springSecurityFilterChain");
        registration.addUrlPatterns("/*");
        registration.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER);
        return registration;
    }*/
/*
    @Bean
    public FilterRegistrationBean backwardsCompatibleScopeParameterRegistration() {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(backwardsCompatibleScopeParameterFilter);
        registration.setName("backwardsCompatibleScopeParameter");
        registration.addUrlPatterns("/*");
        //registration.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER+1);
        return registration;
    }*/

    /*
    @Bean
    public Filter delegatingFilterProxy(){

        //return new DelegatingFilterProxy("org.springframework.security.filterChainProxy");
        return new DelegatingFilterProxy("springSecurityFilterChain");

    }*/

    //@Autowired
    //private FilterChainProxy filterChainProxy;

    /*@Bean
    public Filter backwardsCompatibleScopeParameterFilter(){

        return new BackwardsCompatibleScopeParsingFilter();

    }*/
/*

    @Autowired
    private BackwardsCompatibleScopeParsingFilter backwardsCompatibleScopeParameterFilter;
*/

}
