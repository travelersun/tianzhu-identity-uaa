package com.tianzhu.identity.uaa.appconfig;

import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.filter.DelegatingFilterProxy;

import javax.servlet.DispatcherType;
import javax.servlet.FilterRegistration;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import java.util.EnumSet;

public class UaaWebApplicationInitializer implements ServletContextInitializer {


    @Override
    public void onStartup(ServletContext servletContext) throws ServletException {

        try {



            String filterName = "springSecurityFilterChain";
            DelegatingFilterProxy springSecurityFilterChain = new DelegatingFilterProxy(filterName, (WebApplicationContext) servletContext.getAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE));
            String contextAttribute = "";
            if (contextAttribute != null) {
                springSecurityFilterChain.setContextAttribute(contextAttribute);
            }

            FilterRegistration.Dynamic registration = servletContext.addFilter(filterName, springSecurityFilterChain);
            if (registration == null) {
                throw new IllegalStateException("Duplicate Filter registration for '" + filterName + "'. Check to ensure the Filter is only configured once.");
            } else {
                registration.setAsyncSupported(false);
                //EnumSet<DispatcherType> dispatcherTypes = this.getSecurityDispatcherTypes();
                registration.addMappingForUrlPatterns(null, false, new String[]{"/*"});
            }

        }catch (Exception e) {
            //servletContext.log("Error add HttpSessionEventPublisher Listener : " , e);
        }

    }

}
