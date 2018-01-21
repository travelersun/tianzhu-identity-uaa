package com.tianzhu.identity.uaa.appconfig;

import com.tianzhu.identity.uaa.message.EmailService;
import com.tianzhu.identity.uaa.message.MessageService;
import com.tianzhu.identity.uaa.message.MessageType;
import com.tianzhu.identity.uaa.message.NotificationsService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;

import java.util.ArrayList;

@Configuration
@ImportResource(value = {"classpath:spring-context.xml"})
@Order(Ordered.HIGHEST_PRECEDENCE)
public class UaaBootConfig {

    @Bean
    public MessageService messageService(EmailService emailService, NotificationsService notificationsService, Environment environment) {
        if (environment.getProperty("notifications.url") != null && !environment.getProperty("notifications.url").equals("")) {
            return notificationsService;
        }
        else {
            return emailService;
        }
    }

    @Bean
    public CompositeTokenGranter oauth2TokenGranter(){
        return new CompositeTokenGranter(new ArrayList<>());
    }

    /*@Bean
    public MessageService messageService(){
        return new MessageService() {
            @Override
            public void sendMessage(String email, MessageType messageType, String subject, String htmlContent) {
                System.out.println(htmlContent);
            }
        } ;
    }*/

    /*@Bean
    @Primary
    public AuthenticationEventPublisher authenticationEventPublisher(){

        return new DefaultAuthenticationEventPublisher();

    }*/

}
