package com.tianzhu.identity.uaa.appconfig.filter;

import com.tianzhu.identity.uaa.security.web.SecurityFilterChainPostProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

@Configuration
public class SecurityFilterChainPostProcessorConfig {


    @Value("${require_https:false}")
    Boolean requireHttps;

    @Value("${dump_requests:false}")
    Boolean dumpRequests;

    @Autowired
    @Qualifier("metricsFilter")
    Filter metricsFilter;

    @Autowired
    @Qualifier("headerFilter")
    Filter headerFilter;

    @Autowired
    @Qualifier("utf8ConversionFilter")
    Filter utf8ConversionFilter;

    @Autowired
    @Qualifier("uaacorsFilter")
    Filter uaacorsFilter;

    @Autowired
    @Qualifier("limitedModeUaaFilter")
    Filter limitedModeUaaFilter;

    @Autowired
    @Qualifier("identityZoneResolvingFilter")
    Filter identityZoneResolvingFilter;

    @Autowired
    @Qualifier("disableIdTokenResponseFilter")
    Filter disableIdTokenResponseFilter;

    @Autowired
    @Qualifier("identityZoneSwitchingFilter")
    Filter identityZoneSwitchingFilter;

    @Autowired
    @Qualifier("userManagementSecurityFilter")
    Filter userManagementSecurityFilter;

    @Autowired
    @Qualifier("userManagementFilter")
    Filter userManagementFilter;

    @Autowired
    @Qualifier("sessionResetFilter")
    Filter sessionResetFilter;

    @Autowired
    @Qualifier("oauth2TokenParseFilter")
    Class<?> oauth2TokenParseFilter;


    @Bean
    public SecurityFilterChainPostProcessor securityFilterChainPostProcessor(){

        SecurityFilterChainPostProcessor securityFilterChainPostProcessor = new SecurityFilterChainPostProcessor();

        securityFilterChainPostProcessor.setRequireHttps(requireHttps);
        securityFilterChainPostProcessor.setDumpRequests(dumpRequests);
        securityFilterChainPostProcessor.setRedirectToHttps(Arrays.asList("uiSecurity"));
        securityFilterChainPostProcessor.setIgnore(Arrays.asList("secFilterOpen05Healthz"));
        securityFilterChainPostProcessor.setErrorMap(new HashMap<Class<? extends Exception>, SecurityFilterChainPostProcessor.ReasonPhrase>(){{
            put(org.springframework.dao.NonTransientDataAccessException.class,new SecurityFilterChainPostProcessor.ReasonPhrase(503,"Database unavailable. Retry later."));
        }});


        Map<SecurityFilterChainPostProcessor.FilterPosition, Filter> additionalFilters = new HashMap<SecurityFilterChainPostProcessor.FilterPosition, Filter>();

        /*
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(0),metricsFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(0),headerFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(0),utf8ConversionFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(0),uaacorsFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(0),limitedModeUaaFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(0),identityZoneResolvingFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(0),disableIdTokenResponseFilter);
        */

        List<Filter> filters = new ArrayList<Filter>();
        filters.add(metricsFilter);
        filters.add(headerFilter);
        filters.add(utf8ConversionFilter);
        filters.add(uaacorsFilter);
        filters.add(limitedModeUaaFilter);
        filters.add(identityZoneResolvingFilter);
        filters.add(disableIdTokenResponseFilter);

        SecurityFilterChain fl0 = new DefaultSecurityFilterChain(new RequestMatcher() {
            @Override
            public boolean matches(HttpServletRequest httpServletRequest) {
                return true;
            }
        },filters);

        List<Filter> filters2 = new ArrayList<Filter>();
        filters2.add(identityZoneSwitchingFilter);
        filters2.add(userManagementSecurityFilter);
        filters2.add(userManagementFilter);


        SecurityFilterChain fl2 = new DefaultSecurityFilterChain(new RequestMatcher() {
            @Override
            public boolean matches(HttpServletRequest httpServletRequest) {
                return true;
            }
        },filters2);

        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(0),new FilterChainProxy(fl0));

        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(oauth2TokenParseFilter),new FilterChainProxy(fl2));

        //additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(identityZoneSwitchingFilter.getClass()),userManagementSecurityFilter);
        //additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(userManagementSecurityFilter.getClass()),userManagementFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(2147483647),sessionResetFilter);

        securityFilterChainPostProcessor.setAdditionalFilters(additionalFilters);

        return  securityFilterChainPostProcessor;
    }

}
