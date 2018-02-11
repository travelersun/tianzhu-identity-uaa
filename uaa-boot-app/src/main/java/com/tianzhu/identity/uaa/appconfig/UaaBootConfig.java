package com.tianzhu.identity.uaa.appconfig;

import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;

/**
 * Created by gzcss on 2017/12/13.
 */
@Configuration
@ImportResource({"classpath:spring/application-context.xml"})
//@Order(Ordered.HIGHEST_PRECEDENCE)
public class UaaBootConfig {



    /*@Bean
    public ServletContextInitializer initializer() {
        return new ServletContextInitializer() {

            @Override
            public void onStartup(ServletContext servletContext) throws ServletException {

                servletContext.setInitParameter("p-name", "-value");
            }
        };
    }*/

}
