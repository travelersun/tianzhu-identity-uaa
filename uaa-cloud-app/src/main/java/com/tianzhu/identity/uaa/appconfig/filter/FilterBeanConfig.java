package com.tianzhu.identity.uaa.appconfig.filter;

import com.tianzhu.identity.uaa.authentication.SessionResetFilter;
import com.tianzhu.identity.uaa.authentication.UTF8ConversionFilter;
import com.tianzhu.identity.uaa.metrics.UaaMetricsFilter;
import com.tianzhu.identity.uaa.oauth.DisableIdTokenResponseTypeFilter;
import com.tianzhu.identity.uaa.provider.IdentityProviderProvisioning;
import com.tianzhu.identity.uaa.provider.saml.LoginSamlDiscovery;
import com.tianzhu.identity.uaa.scim.DisableInternalUserManagementFilter;
import com.tianzhu.identity.uaa.scim.DisableUserManagementSecurityFilter;
import com.tianzhu.identity.uaa.security.web.CorsFilter;
import com.tianzhu.identity.uaa.user.UaaUserDatabase;
import com.tianzhu.identity.uaa.web.BackwardsCompatibleScopeParsingFilter;
import com.tianzhu.identity.uaa.web.HeaderFilter;
import com.tianzhu.identity.uaa.web.LimitedModeUaaFilter;
import com.tianzhu.identity.uaa.web.UaaSavedRequestCache;
import com.tianzhu.identity.uaa.zone.IdentityZoneProvisioning;
import com.tianzhu.identity.uaa.zone.IdentityZoneResolvingFilter;
import com.tianzhu.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Configuration
public class FilterBeanConfig {

    @Bean
    public BackwardsCompatibleScopeParsingFilter backwardsCompatibleScopeParameter(){

        return new BackwardsCompatibleScopeParsingFilter();

    }

    @Bean
    public FilterRegistrationBean backwardsCompatibleScopeParameterRegistration() {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(backwardsCompatibleScopeParameter());
        registration.setName("backwardsCompatibleScopeParameter");
        registration.addUrlPatterns("/*");
        registration.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER+1);
        return registration;
    }

    @Bean
    public DisableIdTokenResponseTypeFilter disableIdTokenResponseFilter(@Value("${oauth.id_token.disable:false}") boolean idTokendisable){

        return new DisableIdTokenResponseTypeFilter(idTokendisable, Arrays.asList("/**/oauth/authorize","/oauth/authorize"));

    }

    @Bean
    public FilterRegistrationBean registration2(@Qualifier("disableIdTokenResponseFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }



    @Bean
    public UTF8ConversionFilter utf8ConversionFilter(){
        return new UTF8ConversionFilter();
    }

    @Bean
    public FilterRegistrationBean registration3(@Qualifier("utf8ConversionFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public CorsFilter uaacorsFilter(@Value("#{@config['cors']==null ? T(java.util.Arrays).asList('.*') :\n" +
            "                           @config['cors']['default']==null ? T(java.util.Arrays).asList('.*') :\n" +
            "                           @config['cors']['default']['allowed']==null ? T(java.util.Arrays).asList('.*') :\n" +
            "                           @config['cors']['default']['allowed']['uris']==null ? T(java.util.Arrays).asList('.*') :\n" +
            "                           @config['cors']['default']['allowed']['uris']}") List<String> corsAllowedUris,
                                 @Value("#{@config['cors']==null ? T(java.util.Arrays).asList('.*') :\n" +
                                         "                           @config['cors']['default']==null ? T(java.util.Arrays).asList('.*') :\n" +
                                         "                           @config['cors']['default']['allowed']==null ? T(java.util.Arrays).asList('.*') :\n" +
                                         "                           @config['cors']['default']['allowed']['origins']==null ? T(java.util.Arrays).asList('.*') :\n" +
                                         "                           @config['cors']['default']['allowed']['origins']}") List<String> corsAllowedOrigins,
                                 @Value("#{@config['cors']==null ? T(java.util.Arrays).asList('Accept','Authorization','Content-Type','Accept-Language','Content-Language') :\n" +
                                         "                           @config['cors']['default']==null ? T(java.util.Arrays).asList('Accept','Authorization','Content-Type','Accept-Language','Content-Language') :\n" +
                                         "                           @config['cors']['default']['allowed']==null ? T(java.util.Arrays).asList('Accept','Authorization','Content-Type','Accept-Language','Content-Language') :\n" +
                                         "                           @config['cors']['default']['allowed']['headers']==null ? T(java.util.Arrays).asList('Accept','Authorization','Content-Type','Accept-Language','Content-Language') :\n" +
                                         "                           @config['cors']['default']['allowed']['headers']}") List<String> corsAllowedHeaders,
                                 @Value("#{@config['cors']==null ? T(java.util.Arrays).asList('GET','POST','PUT','OPTIONS','DELETE','PATCH') :\n" +
                                         "                           @config['cors']['default']==null ? T(java.util.Arrays).asList('GET','POST','PUT','OPTIONS','DELETE','PATCH') :\n" +
                                         "                           @config['cors']['default']['allowed']==null ? T(java.util.Arrays).asList('GET','POST','PUT','OPTIONS','DELETE','PATCH') :\n" +
                                         "                           @config['cors']['default']['allowed']['methods']==null ? T(java.util.Arrays).asList('GET','POST','PUT','OPTIONS','DELETE','PATCH') :\n" +
                                         "                           @config['cors']['default']['allowed']['methods']}") List<String> corsAllowedMethods,
                                 @Value("#{@config['cors']==null ? false :\n" +
                                         "                           @config['cors']['default']==null ? false :\n" +
                                         "                           @config['cors']['default']['allowed']==null ? false :\n" +
                                         "                           @config['cors']['default']['allowed']['credentials']==null ? false :\n" +
                                         "                           @config['cors']['default']['allowed']['credentials']}") boolean corsAllowedCredentials,
                                 @Value("#{@config['cors']==null ? 1728000 :\n" +
                                         "                           @config['cors']['default']==null ? 1728000 :\n" +
                                         "                           @config['cors']['default']['max_age']==null ? 1728000 :\n" +
                                         "                           @config['cors']['default']['max_age']}") int corsMaxAge,
                                 @Value("#{@config['cors']==null ? T(java.util.Arrays).asList('.*') :\n" +
                                         "                           @config['cors']['xhr']==null ? T(java.util.Arrays).asList('.*') :\n" +
                                         "                           @config['cors']['xhr']['allowed']==null ? T(java.util.Arrays).asList('.*') :\n" +
                                         "                           @config['cors']['xhr']['allowed']['uris']==null ? T(java.util.Arrays).asList('.*') :\n" +
                                         "                           @config['cors']['xhr']['allowed']['uris']}") List<String> corsXhrAllowedUris,
                                 @Value("#{@config['cors']==null ? T(java.util.Arrays).asList('.*') :\n" +
                                         "                           @config['cors']['xhr']==null ? T(java.util.Arrays).asList('.*') :\n" +
                                         "                           @config['cors']['xhr']['allowed']==null ? T(java.util.Arrays).asList('.*') :\n" +
                                         "                           @config['cors']['xhr']['allowed']['origins']==null ? T(java.util.Arrays).asList('.*') :\n" +
                                         "                           @config['cors']['xhr']['allowed']['origins']}") List<String> corsXhrAllowedOrigins,
                                 @Value("#{@config['cors']==null ? T(java.util.Arrays).asList('Accept','Authorization','Content-Type','Accept-Language','Content-Language', 'X-Requested-With') :\n" +
                                         "                           @config['cors']['xhr']==null ? T(java.util.Arrays).asList('Accept','Authorization','Content-Type','Accept-Language','Content-Language', 'X-Requested-With') :\n" +
                                         "                           @config['cors']['xhr']['allowed']==null ? T(java.util.Arrays).asList('Accept','Authorization','Content-Type','Accept-Language','Content-Language', 'X-Requested-With') :\n" +
                                         "                           @config['cors']['xhr']['allowed']['headers']==null ? T(java.util.Arrays).asList('Accept','Authorization','Content-Type','Accept-Language','Content-Language', 'X-Requested-With') :\n" +
                                         "                           @config['cors']['xhr']['allowed']['headers']}") List<String> corsXhrAllowedHeaders,
                                 @Value("#{@config['cors']==null ? T(java.util.Arrays).asList('GET','OPTIONS') :\n" +
                                         "                           @config['cors']['xhr']==null ? T(java.util.Arrays).asList('GET','OPTIONS') :\n" +
                                         "                           @config['cors']['xhr']['allowed']==null ? T(java.util.Arrays).asList('GET','OPTIONS') :\n" +
                                         "                           @config['cors']['xhr']['allowed']['methods']==null ? T(java.util.Arrays).asList('GET','OPTIONS') :\n" +
                                         "                           @config['cors']['xhr']['allowed']['methods']}") List<String> corsXhrAllowedMethods,
                                 @Value("#{@config['cors']==null ? true :\n" +
                                         "                           @config['cors']['xhr']==null ? true :\n" +
                                         "                           @config['cors']['xhr']['allowed']==null ? true :\n" +
                                         "                           @config['cors']['xhr']['allowed']['credentials']==null ? true :\n" +
                                         "                           @config['cors']['xhr']['allowed']['credentials']}") boolean corsXhrAllowedCredentials,
                                 @Value("#{@config['cors']==null ? 1728000 :\n" +
                                         "                           @config['cors']['xhr']==null ? 1728000 :\n" +
                                         "                           @config['cors']['xhr']['max_age']==null ? 1728000 :\n" +
                                         "                           @config['cors']['xhr']['max_age']}") int corsXhrMaxAge
                                 ){

        CorsFilter corsFilter = new CorsFilter();

        corsFilter.setCorsAllowedUris(corsAllowedUris);
        corsFilter.setCorsAllowedOrigins(corsAllowedOrigins);
        corsFilter.setCorsAllowedHeaders(corsAllowedHeaders);
        corsFilter.setCorsAllowedMethods(corsAllowedMethods);
        corsFilter.setCorsAllowedCredentials(corsAllowedCredentials);
        corsFilter.setCorsMaxAge(corsMaxAge);
        corsFilter.setCorsXhrAllowedUris(corsXhrAllowedUris);
        corsFilter.setCorsXhrAllowedOrigins(corsXhrAllowedOrigins);
        corsFilter.setCorsXhrAllowedHeaders(corsXhrAllowedHeaders);
        corsFilter.setCorsXhrAllowedMethods(corsXhrAllowedMethods);
        corsFilter.setCorsXhrAllowedCredentials(corsXhrAllowedCredentials);
        corsFilter.setCorsXhrMaxAge(corsXhrMaxAge);

        return corsFilter;

    }

    @Bean
    public FilterRegistrationBean registration4(@Qualifier("uaacorsFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public Class<?> oauth2TokenParseFilter() throws ClassNotFoundException {

        return java.lang.Class.forName("org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter");

    }

    @Bean
    public HeaderFilter headerFilter(@Value("#{@config['servlet']==null ? @defaultFilteredHeaders : @config['servlet']['filtered-headers'] == null ? @defaultFilteredHeaders : @config['servlet']['filtered-headers']}")
                                                 List<String> filteredHeaderNames){

        return new HeaderFilter(filteredHeaderNames);

    }

    @Bean
    public FilterRegistrationBean registration5(@Qualifier("headerFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public UaaMetricsFilter metricsFilter(@Value("${metrics.enabled:true}") boolean enabled,@Value("${metrics.perRequestMetrics:false}") boolean perRequestMetrics) throws IOException {

        UaaMetricsFilter metricsFilter = new UaaMetricsFilter();
        metricsFilter.setEnabled(enabled);
        metricsFilter.setPerRequestMetrics(perRequestMetrics);
        return metricsFilter;
    }

    @Bean
    public FilterRegistrationBean registration6(@Qualifier("metricsFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public DisableUserManagementSecurityFilter userManagementSecurityFilter(@Qualifier("identityProviderProvisioning") IdentityProviderProvisioning identityProviderProvisioning){
        return new DisableUserManagementSecurityFilter(identityProviderProvisioning);
    }

    @Bean
    public FilterRegistrationBean registration7(@Qualifier("userManagementSecurityFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public DisableInternalUserManagementFilter userManagementFilter(@Qualifier("identityProviderProvisioning") IdentityProviderProvisioning identityProviderProvisioning){
        return new DisableInternalUserManagementFilter(identityProviderProvisioning);
    }

    @Bean
    public FilterRegistrationBean registration8(@Qualifier("userManagementFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public IdentityZoneResolvingFilter identityZoneResolvingFilter(@Qualifier("identityZoneProvisioning") IdentityZoneProvisioning identityZoneProvisioning,
                                                                   @Value("#{T(com.tianzhu.identity.uaa.util.UaaUrlUtils).getHostForURI(@uaaUrl)}") String defaulthostnames1,
                                                                   @Value("#{T(com.tianzhu.identity.uaa.util.UaaUrlUtils).getHostForURI(@loginUrl)}") String defaulthostnames2,
                                                                   @Value("#{@config['zones']==null ? null : @config['zones']['internal']==null ? null : @config['zones']['internal']['hostnames']}") Set<String> addithostnames){
        IdentityZoneResolvingFilter identityZoneResolvingFilter  = new IdentityZoneResolvingFilter();
        identityZoneResolvingFilter.setIdentityZoneProvisioning(identityZoneProvisioning);

        Set<String> defaulthostnames = new HashSet<String>();
        defaulthostnames.add(defaulthostnames1);
        defaulthostnames.add(defaulthostnames2);
        defaulthostnames.add("localhost");

        identityZoneResolvingFilter.setDefaultInternalHostnames(defaulthostnames);
        identityZoneResolvingFilter.setAdditionalInternalHostnames(addithostnames);

        return identityZoneResolvingFilter;
    }

    @Bean
    public FilterRegistrationBean registration9(@Qualifier("identityZoneResolvingFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public SessionResetFilter sessionResetFilter(@Qualifier("userDatabase") UaaUserDatabase userDatabase){
        return new SessionResetFilter(new DefaultRedirectStrategy(),"/login",userDatabase);
    }

    @Bean
    public FilterRegistrationBean registration10(@Qualifier("sessionResetFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public IdentityZoneSwitchingFilter identityZoneSwitchingFilter(@Qualifier("identityZoneProvisioning") IdentityZoneProvisioning identityZoneProvisioning){
        return new IdentityZoneSwitchingFilter(identityZoneProvisioning);
    }

    @Bean
    public FilterRegistrationBean registration11(@Qualifier("identityZoneSwitchingFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public LimitedModeUaaFilter limitedModeUaaFilter(@Value("${uaa.limitedFunctionality.statusFile:#{null}}") File statusFile,
                                                     @Value("#{@config['uaa']==null ? null :\n" +
                                                             "                           @config['uaa']['limitedFunctionality']==null ? null :\n" +
                                                             "                           @config['uaa']['limitedFunctionality']['whitelist']==null ? null :\n" +
                                                             "                           @config['uaa']['limitedFunctionality']['whitelist']['endpoints']}") Set<String> permittedEndpoints,
                                                     @Value("#{@config['uaa']==null ? null :\n" +
                                                             "                           @config['uaa']['limitedFunctionality']==null ? null :\n" +
                                                             "                           @config['uaa']['limitedFunctionality']['whitelist']==null ? null :\n" +
                                                             "                           @config['uaa']['limitedFunctionality']['whitelist']['methods']}") Set<String> permittedMethods){

        LimitedModeUaaFilter limitedModeUaaFilter = new LimitedModeUaaFilter();
        limitedModeUaaFilter.setStatusFile(statusFile);
        limitedModeUaaFilter.setPermittedEndpoints(permittedEndpoints);
        limitedModeUaaFilter.setPermittedMethods(permittedMethods);

        return limitedModeUaaFilter;

    }

    @Bean
    public FilterRegistrationBean registration12(@Qualifier("limitedModeUaaFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public UaaSavedRequestCache clientRedirectStateCache(@Qualifier("uiAuthorizeRequestMatcher") RequestMatcher requestMatcher){
        UaaSavedRequestCache clientRedirectStateCache = new UaaSavedRequestCache();
        clientRedirectStateCache.setRequestMatcher(requestMatcher);
        return clientRedirectStateCache;
    }

    @Bean
    public FilterRegistrationBean registration13(@Qualifier("clientRedirectStateCache") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public LoginSamlDiscovery samlIDPDiscovery(@Qualifier("basicContextProvider") SAMLContextProvider contextProvider,
                                               @Qualifier("metadata") MetadataManager metadata){
        LoginSamlDiscovery samlIDPDiscovery = new LoginSamlDiscovery();
        samlIDPDiscovery.setContextProvider(contextProvider);
        samlIDPDiscovery.setMetadata(metadata);
        return samlIDPDiscovery;
    }

    @Bean
    public FilterRegistrationBean registration14(@Qualifier("samlIDPDiscovery") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

}
