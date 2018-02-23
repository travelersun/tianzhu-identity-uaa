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
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.openid.OpenIDAttribute;
import org.springframework.security.openid.OpenIDAuthenticationToken;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.Filter;

@Order(185)
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled=true, prePostEnabled=true)
public class OpenIdSecurity extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("metadataGeneratorFilter")
    Filter metadataGeneratorFilter;

    @Autowired
    @Qualifier("httpsHeaderFilter")
    Filter httpsHeaderFilter;

    @Autowired
    @Qualifier("idpMetadataGeneratorFilter")
    Filter idpMetadataGeneratorFilter;

    @Autowired
    @Qualifier("samlFilter")
    Filter samlFilter;

    @Autowired
    @Qualifier("samlIdpLoginFilter")
    Filter samlIdpLoginFilter;

    @Autowired
    @Qualifier("oauth2ClientFilter")
    Filter oauth2ClientFilter;

    @Autowired
    @Qualifier("logoutHandler")
    LogoutSuccessHandler logoutHandler;

    @Autowired
    @Qualifier("openIdUserDetailsService")
    AuthenticationUserDetailsService<OpenIDAuthenticationToken> openIdUserDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        OpenIDAttribute attribute1 = new OpenIDAttribute("email", "http://schema.openid.net/contact/email");
        attribute1.setRequired(true);

        OpenIDAttribute attribute2 = new OpenIDAttribute("fullname", "http://schema.openid.net/namePerson");
        attribute2.setRequired(true);


        OpenIDAttribute attribute3 = new OpenIDAttribute("email", "http://axschema.org/contact/email");
        attribute3.setCount(1);
        attribute3.setRequired(true);

        OpenIDAttribute attribute4 = new OpenIDAttribute("firstname", "http://axschema.org/namePerson/first");
        attribute4.setRequired(true);

        OpenIDAttribute attribute5 = new OpenIDAttribute("lastname", "http://axschema.org/namePerson/last");
        attribute5.setRequired(true);

        OpenIDAttribute attribute6 = new OpenIDAttribute("fullname", "http://axschema.org/namePerson");
        attribute6.setRequired(true);

        http
                .authorizeRequests().antMatchers("/**").fullyAuthenticated()
                .and()
                .addFilterBefore(metadataGeneratorFilter, ChannelProcessingFilter.class)
                .addFilterAfter(httpsHeaderFilter, ChannelProcessingFilter.class)
                .addFilterBefore(idpMetadataGeneratorFilter, BasicAuthenticationFilter.class)
                .addFilterAfter(samlFilter, BasicAuthenticationFilter.class)
                .addFilterAfter(samlIdpLoginFilter, FilterSecurityInterceptor.class)
                .addFilterAfter(oauth2ClientFilter, ExceptionTranslationFilter.class)
                .logout().logoutUrl("/logout").logoutSuccessHandler(logoutHandler)
                .and()
                .openidLogin().loginPage("/login").authenticationUserDetailsService(openIdUserDetailsService).failureUrl("/login?error=true")
                .attributeExchange(".*myopenid.com.*").attribute(attribute1).attribute(attribute2)
                .and().attributeExchange(".*").attribute(attribute3).attribute(attribute4).attribute(attribute5).attribute(attribute6)
                .and().and().anonymous().disable().csrf().disable();
    }


}
