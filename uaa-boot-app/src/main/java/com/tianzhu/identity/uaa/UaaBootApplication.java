package com.tianzhu.identity.uaa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.web.servlet.ErrorPage;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;

/**
 * Created by gzcss on 2017/12/13.
 */
@SpringBootApplication
public class UaaBootApplication {

    public static void main(String[] args) throws Exception {
        ConfigurableApplicationContext cx = SpringApplication.run(UaaBootApplication.class,args);
    }

    @Bean
    public EmbeddedServletContainerCustomizer containerCustomizer() {

        return (container -> {
            //ErrorPage error401Page = new ErrorPage(HttpStatus.UNAUTHORIZED, "/401.html");
            ErrorPage error404Page = new ErrorPage(HttpStatus.NOT_FOUND, "/error404");
            ErrorPage error500Page = new ErrorPage(HttpStatus.INTERNAL_SERVER_ERROR, "/error500");

            container.addErrorPages(error404Page, error500Page);
        });
    }

}
