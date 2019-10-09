package com.tianzhu.identity.uaa.appconfig.filter;

import com.tianzhu.identity.uaa.account.ResetPasswordAuthenticationFilter;
import com.tianzhu.identity.uaa.account.ResetPasswordService;
import com.tianzhu.identity.uaa.authentication.AuthzAuthenticationFilter;
import com.tianzhu.identity.uaa.codestore.ExpiringCodeStore;
import com.tianzhu.identity.uaa.invitations.InvitationsAuthenticationTrustResolver;
import com.tianzhu.identity.uaa.login.AccountSavingAuthenticationSuccessHandler;
import com.tianzhu.identity.uaa.security.web.HttpsHeaderFilter;
import com.tianzhu.identity.uaa.web.NoOpFilter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.*;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Configuration
public class LoginFilterBeanConfig {

    @Bean
    public SecurityContextPersistenceFilter acceptInvitationSecurityContextPersistenceFilter(){

        HttpSessionSecurityContextRepository invitationsContextRepo = new HttpSessionSecurityContextRepository();
        invitationsContextRepo.setTrustResolver(new InvitationsAuthenticationTrustResolver());

        return new SecurityContextPersistenceFilter(invitationsContextRepo);
    }

    @Bean
    public FilterRegistrationBean registration15(@Qualifier("acceptInvitationSecurityContextPersistenceFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public ResetPasswordAuthenticationFilter resetPasswordAuthenticationFilter(@Qualifier("resetPasswordService") ResetPasswordService service,
                                                                               @Qualifier("accountSavingAuthenticationSuccessHandler") AuthenticationSuccessHandler handler,
                                                                               @Qualifier("resetPasswordEntryPoint") AuthenticationEntryPoint entryPoint,
                                                                               @Qualifier("codeStore") ExpiringCodeStore expiringCodeStore){

        ResetPasswordAuthenticationFilter resetPasswordAuthenticationFilter = new ResetPasswordAuthenticationFilter(service,handler,entryPoint,expiringCodeStore);
        return resetPasswordAuthenticationFilter;
    }

    @Bean
    public FilterRegistrationBean registration16(@Qualifier("resetPasswordAuthenticationFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public LogoutFilter logoutFilter(@Qualifier("logoutHandler") LogoutSuccessHandler logoutSuccessHandler,
                                     @Qualifier("uaaAuthenticationFailureHandler") LogoutHandler handler,
                                     @Qualifier("loginCookieCsrfRepository") CsrfTokenRepository csrfTokenRepository,
                                     @Qualifier("uiLogoutRequestMatcher") RequestMatcher logoutRequestMatcher){

        CsrfLogoutHandler csrfLogoutHandler = new CsrfLogoutHandler(csrfTokenRepository);
        CookieClearingLogoutHandler CookieClearingLogoutHandler = new CookieClearingLogoutHandler("JSESSIONID");

        LogoutFilter logoutFilter = new LogoutFilter(logoutSuccessHandler,handler,new SecurityContextLogoutHandler(),csrfLogoutHandler,CookieClearingLogoutHandler);

        logoutFilter.setLogoutRequestMatcher(logoutRequestMatcher);
        return logoutFilter;
    }

    @Bean
    public FilterRegistrationBean registration17(@Qualifier("logoutFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public HttpsHeaderFilter httpsHeaderFilter(){

        return new HttpsHeaderFilter();
    }

    @Bean
    public FilterRegistrationBean registration18(@Qualifier("httpsHeaderFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public NoOpFilter metadataGeneratorFilter(){

        return new NoOpFilter();
    }

    @Bean
    public FilterRegistrationBean registration19(@Qualifier("metadataGeneratorFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public NoOpFilter samlFilter(){

        return new NoOpFilter();
    }

    @Bean
    public FilterRegistrationBean registration20(@Qualifier("samlFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public FilterChainProxy samlIdpLoginFilter(@Qualifier("samlSecurityContextPersistenceFilter") Filter samlSecurityContextPersistenceFilter,@Qualifier("samlIdpWebSsoProcessingFilter") Filter samlIdpWebSsoProcessingFilter){

        RequestMatcher requestMatcher = new AntPathRequestMatcher("/saml/idp/SSO/**");

        SecurityFilterChain chain = new DefaultSecurityFilterChain(requestMatcher,samlSecurityContextPersistenceFilter,samlIdpWebSsoProcessingFilter);

        FilterChainProxy samlIdpLoginFilter = new FilterChainProxy(chain);

        return samlIdpLoginFilter;
    }

    @Bean
    public FilterRegistrationBean registration21(@Qualifier("samlIdpLoginFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public AuthzAuthenticationFilter autologinAuthenticationFilter(@Qualifier("autologinAuthenticationManager") AuthenticationManager authenticationManager,
                                                                   @Qualifier("accountSavingAuthenticationSuccessHandler") AccountSavingAuthenticationSuccessHandler successHandler){

        AuthzAuthenticationFilter autologinAuthenticationFilter = new AuthzAuthenticationFilter(authenticationManager);
        autologinAuthenticationFilter.setParameterNames(Arrays.asList("code","response_type"));
        Set<String> methods = new HashSet<String>();
        methods.add("GET");
        methods.add("POST");
        autologinAuthenticationFilter.setMethods(methods);
        autologinAuthenticationFilter.setSuccessHandler(successHandler);
        return autologinAuthenticationFilter;
    }

    @Bean
    public FilterRegistrationBean registration22(@Qualifier("autologinAuthenticationFilter") Filter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

}
