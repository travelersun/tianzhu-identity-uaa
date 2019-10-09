package com.tianzhu.identity.uaa.appconfig;

import com.tianzhu.identity.uaa.impl.config.EnvironmentMapFactoryBean;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.session.web.http.CookieHttpSessionStrategy;
import org.springframework.session.web.http.DefaultCookieSerializer;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;

/**
 * Created by gzcss on 2017/12/13.
 */
@Configuration
@ImportResource({"classpath:spring/application-context.xml"})
//@Order(Ordered.HIGHEST_PRECEDENCE)
public class UaaBootConfig {



    @Bean
    public EnvironmentMapFactoryBean config() {
        return new EnvironmentMapFactoryBean();
    }


    @Bean
    public CookieHttpSessionStrategy cookieHttpSessionStrategy(){
        CookieHttpSessionStrategy cookieStrategy=new CookieHttpSessionStrategy();
        DefaultCookieSerializer cookieSerializer=new DefaultCookieSerializer();
        cookieSerializer.setCookieName("UAASESSION");
        cookieSerializer.setCookieMaxAge(1800);
        cookieStrategy.setCookieSerializer(cookieSerializer);
        return cookieStrategy;
    }



}
