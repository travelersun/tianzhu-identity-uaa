package com.tianzhu.identity.uaa.appconfig;

import com.tianzhu.identity.uaa.web.RecognizeFailureDispatcherServlet;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Created by gzcss on 2017/12/13.
 */
@Configuration
public class UaaServletConfig {


    @Bean
    public ServletRegistrationBean indexServletRegistration() {
        ServletRegistrationBean registration = new ServletRegistrationBean(new RecognizeFailureDispatcherServlet());
        //registration.addInitParameter("contextInitializerClasses","com.tianzhu.identity.uaa.appconfig.UaaWebApplicationInitializer");
        registration.addInitParameter("contextConfigLocation","classpath:spring-servlet.xml");
        //registration.addInitParameter("environmentConfigDefaults","application.yml,uaa.yml,login.yml");
        //registration.addInitParameter("environmentConfigLocations","classpath:application.yml,classpath:uaa.yml,classpath:login.yml");
        registration.setName("spring");
        registration.addUrlMappings("/");
        //registration.setOrder(10);
        registration.setLoadOnStartup(1);
        return registration;
    }
}
