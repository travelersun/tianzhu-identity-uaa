package com.tianzhu.identity.uaa.appconfig;

import com.tianzhu.identity.uaa.web.BackwardsCompatibleScopeParsingFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.web.filter.DelegatingFilterProxy;

import javax.servlet.Filter;

/**
 * Created by gzcss on 2017/12/13.
 */
@Configuration
public class UaaFilterConfig {


    @Bean
    public FilterRegistrationBean springSecurityFilterChainRegistration() {
        FilterRegistrationBean registration = new FilterRegistrationBean(delegatingFilterProxy());
        registration.addInitParameter("contextAttribute","org.springframework.web.servlet.FrameworkServlet.CONTEXT.spring");
        registration.setName("springSecurityFilterChain");
        registration.addUrlPatterns("/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }

    @Bean
    public FilterRegistrationBean backwardsCompatibleScopeParameterRegistration() {
        FilterRegistrationBean registration = new FilterRegistrationBean(backwardsCompatibleScopeParameterFilter);
        registration.setName("backwardsCompatibleScopeParameter");
        registration.addUrlPatterns("/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE+1);
        return registration;
    }

    @Bean
    public Filter delegatingFilterProxy(){

        return new DelegatingFilterProxy("org.springframework.security.filterChainProxy");

    }

    //@Autowired
    //private FilterChainProxy filterChainProxy;

    /*@Bean
    public Filter backwardsCompatibleScopeParameterFilter(){

        return new BackwardsCompatibleScopeParsingFilter();

    }*/

    @Autowired
    private BackwardsCompatibleScopeParsingFilter backwardsCompatibleScopeParameterFilter;

}
