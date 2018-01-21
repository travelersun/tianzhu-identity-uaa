package com.tianzhu.identity.uaa.appconfig;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.web.servlet.ErrorPage;
import org.springframework.boot.web.support.SpringBootServletInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.web.WebApplicationInitializer;
import org.springframework.web.filter.DelegatingFilterProxy;

import javax.servlet.FilterRegistration;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;

/**
 * Created by gzcss on 2017/12/13.
 */
@SpringBootApplication(scanBasePackages = {"com.tianzhu.identity.uaa.appconfig"})
public class UaaApplication  {

    public static void main(String[] args) throws Exception {
        ConfigurableApplicationContext cx = SpringApplication.run(UaaApplication.class,args);
/*
        String [] beans = cx.getBeanDefinitionNames();

        Arrays.sort(beans);

        for (String b: beans
             ) {

            System.out.println(b);

        }*/
    }


    @Bean
    public EmbeddedServletContainerCustomizer containerCustomizer() {

        return (container -> {
            //ErrorPage error401Page = new ErrorPage(HttpStatus.UNAUTHORIZED, "/401.html");
            ErrorPage error404Page = new ErrorPage(HttpStatus.NOT_FOUND, "/error404");
            ErrorPage error500Page = new ErrorPage(HttpStatus.INTERNAL_SERVER_ERROR, "/error500");

            container.addErrorPages(error404Page, error500Page);

            container.addInitializers(new UaaWebApplicationInitializer());
        });
    }

}
