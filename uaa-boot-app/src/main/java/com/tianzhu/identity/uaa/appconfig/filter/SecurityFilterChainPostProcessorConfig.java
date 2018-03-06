package com.tianzhu.identity.uaa.appconfig.filter;

import com.tianzhu.identity.uaa.security.web.SecurityFilterChainPostProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import javax.servlet.Filter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

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
    Object oauth2TokenParseFilter;

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

        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(0),metricsFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(1),headerFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(2),utf8ConversionFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(3),uaacorsFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(4),limitedModeUaaFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(5),identityZoneResolvingFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(6),disableIdTokenResponseFilter);

        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(oauth2TokenParseFilter.getClass()),identityZoneSwitchingFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(identityZoneSwitchingFilter.getClass()),userManagementSecurityFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(userManagementSecurityFilter.getClass()),userManagementFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(102),sessionResetFilter);

        securityFilterChainPostProcessor.setAdditionalFilters(additionalFilters);

        return  securityFilterChainPostProcessor;
    }

}
