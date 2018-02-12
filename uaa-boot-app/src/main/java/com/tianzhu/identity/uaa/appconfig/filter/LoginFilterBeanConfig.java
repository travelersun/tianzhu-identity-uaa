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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.*;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

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
    public ResetPasswordAuthenticationFilter resetPasswordAuthenticationFilter(@Qualifier("resetPasswordService") ResetPasswordService service,
                                                                               @Qualifier("accountSavingAuthenticationSuccessHandler") AuthenticationSuccessHandler handler,
                                                                               @Qualifier("resetPasswordEntryPoint") AuthenticationEntryPoint entryPoint,
                                                                               @Qualifier("codeStore") ExpiringCodeStore expiringCodeStore){

        ResetPasswordAuthenticationFilter resetPasswordAuthenticationFilter = new ResetPasswordAuthenticationFilter(service,handler,entryPoint,expiringCodeStore);
        return resetPasswordAuthenticationFilter;
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
    public HttpsHeaderFilter httpsHeaderFilter(){

        return new HttpsHeaderFilter();
    }

    @Bean
    public NoOpFilter metadataGeneratorFilter(){

        return new NoOpFilter();
    }

    @Bean
    public NoOpFilter samlFilter(){

        return new NoOpFilter();
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

}
