package com.tianzhu.identity.uaa.appconfig;

import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.context.request.RequestContextListener;

/**
 * Created by gzcss on 2017/12/13.
 */
@Configuration
public class UaaListenerConfig {

    @Bean
    public ServletListenerRegistrationBean servletListenerRegistrationBean(){
        ServletListenerRegistrationBean servletListenerRegistrationBean = new ServletListenerRegistrationBean();
        servletListenerRegistrationBean.setListener(new RequestContextListener());
        //servletListenerRegistrationBean.setOrder(10);
        return servletListenerRegistrationBean;
    }

    @Bean
    public ServletListenerRegistrationBean httpSessionEventPublisherListenerRegistrationBean(){
        ServletListenerRegistrationBean servletListenerRegistrationBean = new ServletListenerRegistrationBean();
        servletListenerRegistrationBean.setListener(new HttpSessionEventPublisher());
        //servletListenerRegistrationBean.setOrder(10);
        return servletListenerRegistrationBean;
    }

}
