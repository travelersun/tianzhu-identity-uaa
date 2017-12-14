package com.tianzhu.identity.uaa;

import com.tianzhu.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityFilterAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;

/**
 * Created by gzcss on 2017/12/13.
 */
@SpringBootApplication(scanBasePackages = {"com.tianzhu.identity.uaa.appconfig"},exclude = {SecurityFilterAutoConfiguration.class})
public class UaaApplication {

    public static void main(String[] args) throws Exception {
        //System.setProperty("environmentYamlKey", "environmentYamlKey");
        //new SpringApplicationBuilder(UaaApplication.class).initializers(new YamlServletProfileInitializer()).run(args);

        SpringApplication.run(UaaApplication.class,args);
        int i = 0;
    }

}
