package com.tianzhu.identity.uaa.impl.config;

import com.tianzhu.identity.uaa.account.AccountCreationService;
import com.tianzhu.identity.uaa.account.AccountsController;
import com.tianzhu.identity.uaa.message.EmailService;
import com.tianzhu.identity.uaa.message.MessageService;
import com.tianzhu.identity.uaa.message.NotificationsService;
import com.tianzhu.identity.uaa.provider.IdentityProviderProvisioning;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
public class LoginServerConfig {

    @Bean
    public AccountsController accountsController(AccountCreationService accountCreationService, IdentityProviderProvisioning identityProviderProvisioning) {
        return new AccountsController(accountCreationService, identityProviderProvisioning);
    }

    @Bean
    public MessageService messageService(EmailService emailService, NotificationsService notificationsService, Environment environment) {
        if (environment.getProperty("notifications.url") != null && !environment.getProperty("notifications.url").equals("")) {
            return notificationsService;
        }
        else {
            return emailService;
        }
    }
}
