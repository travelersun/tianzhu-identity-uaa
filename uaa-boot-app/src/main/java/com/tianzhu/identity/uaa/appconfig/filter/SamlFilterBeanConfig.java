package com.tianzhu.identity.uaa.appconfig.filter;

import com.tianzhu.identity.uaa.authentication.UaaSamlLogoutFilter;
import com.tianzhu.identity.uaa.provider.saml.ZoneAwareMetadataDisplayFilter;
import com.tianzhu.identity.uaa.provider.saml.idp.IdpMetadataDisplayFilter;
import com.tianzhu.identity.uaa.provider.saml.idp.IdpMetadataGenerator;
import com.tianzhu.identity.uaa.provider.saml.idp.IdpMetadataGeneratorFilter;
import com.tianzhu.identity.uaa.provider.saml.idp.IdpMetadataManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@Configuration
public class SamlFilterBeanConfig {


    @Bean
    public SAMLProcessingFilter samlIdpWebSsoProcessingFilter(@Qualifier("samlIdpAuthenticationManager") AuthenticationManager authenticationManager,
                                                              @Qualifier("samlIdpSuccessHandler") AuthenticationSuccessHandler successHandler,
                                                              @Qualifier("idpContextProvider") SAMLContextProvider contextProvider,
                                                              @Qualifier("idpSamlProcessor") SAMLProcessor processor,
                                                              @Qualifier("sessionFixationProtectionStrategy") SessionAuthenticationStrategy sessionStrategy){

        SAMLProcessingFilter samlIdpWebSsoProcessingFilter = new SAMLProcessingFilter();
        samlIdpWebSsoProcessingFilter.setFilterProcessesUrl("/saml/idp/SSO");
        samlIdpWebSsoProcessingFilter.setAuthenticationManager(authenticationManager);
        samlIdpWebSsoProcessingFilter.setAuthenticationSuccessHandler(successHandler);
        samlIdpWebSsoProcessingFilter.setContextProvider(contextProvider);
        samlIdpWebSsoProcessingFilter.setSAMLProcessor(processor);
        samlIdpWebSsoProcessingFilter.setSessionAuthenticationStrategy(sessionStrategy);

        return samlIdpWebSsoProcessingFilter;
    }

    @Bean
    public IdpMetadataGeneratorFilter idpMetadataGeneratorFilter(@Qualifier("zoneAwareIdpMetadataGenerator") IdpMetadataGenerator generator,
                                                                 @Qualifier("idpMetadataDisplayFilter") MetadataDisplayFilter displayFilter,
                                                                 @Qualifier("idpMetadataManager") IdpMetadataManager manager){
        IdpMetadataGeneratorFilter idpMetadataGeneratorFilter = new IdpMetadataGeneratorFilter(generator);
        idpMetadataGeneratorFilter.setDisplayFilter(displayFilter);
        idpMetadataGeneratorFilter.setManager(manager);

        return idpMetadataGeneratorFilter;
    }

    @Bean
    public IdpMetadataDisplayFilter idpMetadataDisplayFilter(@Qualifier("idpContextProvider") SAMLContextProvider contextProvider,
                                                             @Qualifier("idpMetadataManager") MetadataManager manager,
                                                             @Qualifier("idpZoneAwareSamlKeyManager") KeyManager keyManager){
        IdpMetadataDisplayFilter idpMetadataDisplayFilter = new IdpMetadataDisplayFilter();
        idpMetadataDisplayFilter.setContextProvider(contextProvider);
        idpMetadataDisplayFilter.setManager(manager);
        idpMetadataDisplayFilter.setFilterProcessesUrl("/saml/idp/metadata");
        idpMetadataDisplayFilter.setKeyManager(keyManager);
        return idpMetadataDisplayFilter;
    }

    @Bean
    public SecurityContextPersistenceFilter samlSecurityContextPersistenceFilter(){
        return new SecurityContextPersistenceFilter();
    }

    @Bean
    public ExceptionTranslationFilter exceptionTranslationFilter(@Qualifier("samlEntryPoint") AuthenticationEntryPoint authenticationEntryPoint){
        return new ExceptionTranslationFilter(authenticationEntryPoint);
    }

    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter(@Qualifier("zoneAwareMetadataGenerator") MetadataGenerator generator,
                                                           @Qualifier("metadata") MetadataManager manager,
                                                           @Qualifier("metadataDisplayFilter") MetadataDisplayFilter displayFilter){

        MetadataGeneratorFilter metadataGeneratorFilter = new MetadataGeneratorFilter(generator);
        metadataGeneratorFilter.setManager(manager);
        metadataGeneratorFilter.setDisplayFilter(displayFilter);
        return metadataGeneratorFilter;
    }

    @Bean
    public ZoneAwareMetadataDisplayFilter metadataDisplayFilter(@Qualifier("zoneAwareMetadataGenerator") MetadataGenerator generator,
                                                                @Qualifier("metadata") MetadataManager manager,
                                                                @Qualifier("basicContextProvider") SAMLContextProvider contextProvider,
                                                                @Qualifier("zoneAwareSamlSpKeyManager") KeyManager keyManager){
        ZoneAwareMetadataDisplayFilter metadataDisplayFilter = new ZoneAwareMetadataDisplayFilter(generator);
        metadataDisplayFilter.setManager(manager);
        metadataDisplayFilter.setContextProvider(contextProvider);
        metadataDisplayFilter.setKeyManager(keyManager);

        return metadataDisplayFilter;
    }

    @Bean
    public SAMLProcessingFilter samlWebSSOProcessingFilter(@Qualifier("samlAuthenticationManager") AuthenticationManager authenticationManager,
                                                           @Qualifier("accountSavingAuthenticationSuccessHandler") AuthenticationSuccessHandler successHandler,
                                                           @Qualifier("samlLoginFailureHandler") AuthenticationFailureHandler failureHandler,
                                                           @Qualifier("basicContextProvider") SAMLContextProvider contextProvider,
                                                           @Qualifier("processor") SAMLProcessor processor,
                                                           @Qualifier("sessionFixationProtectionStrategy") SessionAuthenticationStrategy sessionStrategy){
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager);
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successHandler);
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(failureHandler);
        samlWebSSOProcessingFilter.setContextProvider(contextProvider);
        samlWebSSOProcessingFilter.setSAMLProcessor(processor);
        samlWebSSOProcessingFilter.setSessionAuthenticationStrategy(sessionStrategy);

        return samlWebSSOProcessingFilter;
    }

    @Bean
    public UaaSamlLogoutFilter samlLogoutFilter(@Qualifier("logoutHandler") LogoutSuccessHandler logoutSuccessHandler,
                                                @Qualifier("samlLogoutHandlers") LogoutHandler samlLogoutHandlers,
                                                @Qualifier("redirectSavingSamlContextProvider") SAMLContextProvider contextProvider){
        UaaSamlLogoutFilter samlLogoutFilter = new UaaSamlLogoutFilter(logoutSuccessHandler,samlLogoutHandlers);
        samlLogoutFilter.setContextProvider(contextProvider);

        return samlLogoutFilter;
    }

    @Bean
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter(@Qualifier("samlWhitelistLogoutHandler") LogoutSuccessHandler logoutSuccessHandler,
                                                                 @Qualifier("samlLogoutHandlers") LogoutHandler samlLogoutHandlers,
                                                                 @Qualifier("processor") SAMLProcessor processor){
        SAMLLogoutProcessingFilter samlLogoutProcessingFilter = new SAMLLogoutProcessingFilter(logoutSuccessHandler,samlLogoutHandlers);
        samlLogoutProcessingFilter.setSAMLProcessor(processor);

        return samlLogoutProcessingFilter;
    }

}
