package com.tianzhu.identity.uaa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.SecurityFilterAutoConfiguration;

/**
 * Created by gzcss on 2017/12/13.
 */
@SpringBootApplication(scanBasePackages = {"com.tianzhu.identity.uaa.appconfig"},exclude = {SecurityFilterAutoConfiguration.class})
public class UaaApplication {

    public static void main(String[] args) throws Exception {
         SpringApplication.run(UaaApplication.class,args);
    }

}
