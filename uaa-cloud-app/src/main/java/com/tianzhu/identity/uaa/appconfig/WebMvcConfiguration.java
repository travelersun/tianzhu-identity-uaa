package com.tianzhu.identity.uaa.appconfig;

import com.tianzhu.identity.uaa.web.ForwardAwareInternalResourceViewResolver;
import nz.net.ultraq.thymeleaf.LayoutDialect;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.web.accept.ContentNegotiationManager;
import org.springframework.web.accept.ContentNegotiationManagerFactoryBean;
import org.springframework.web.servlet.config.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.servlet.view.BeanNameViewResolver;
import org.springframework.web.servlet.view.ContentNegotiatingViewResolver;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;
import org.thymeleaf.dialect.IDialect;
import org.thymeleaf.extras.springsecurity4.dialect.SpringSecurityDialect;
import org.thymeleaf.spring4.SpringTemplateEngine;
import org.thymeleaf.spring4.templateresolver.SpringResourceTemplateResolver;
import org.thymeleaf.spring4.view.ThymeleafViewResolver;
import org.thymeleaf.templateresolver.ITemplateResolver;

import java.nio.charset.StandardCharsets;
import java.util.*;

@Configuration
@EnableWebMvc
public class WebMvcConfiguration extends WebMvcConfigurerAdapter {

    @Bean
    @Primary
    public ThymeleafViewResolver thymeleafViewResolver(ApplicationContext context) {
        ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();
        viewResolver.setTemplateEngine(webTemplateEngine(context));
        return viewResolver;
    }

    @Bean
    @Primary
    public SpringTemplateEngine webTemplateEngine(ApplicationContext context) {
        SpringTemplateEngine springTemplateEngine = new SpringTemplateEngine();

        springTemplateEngine.setTemplateResolver(webTemplateResolver(context));

        Set<IDialect> additionalDialects = new HashSet<>();
        additionalDialects.add(new LayoutDialect());
        additionalDialects.add(new SpringSecurityDialect());
        springTemplateEngine.setAdditionalDialects(additionalDialects);

        return springTemplateEngine;
    }

    @Bean
    public ITemplateResolver webTemplateResolver(ApplicationContext context) {
        SpringResourceTemplateResolver templateResolver = baseHtmlTemplateResolver(context);
        templateResolver.setPrefix("classpath:/templates/web/");
        return templateResolver;
    }

    @Bean
    public SpringTemplateEngine mailTemplateEngine(ApplicationContext context) {
        SpringTemplateEngine springTemplateEngine = new SpringTemplateEngine();
        springTemplateEngine.setTemplateResolver(mailTemplateResolver(context));
        return springTemplateEngine;
    }

    @Bean
    public ITemplateResolver mailTemplateResolver(ApplicationContext context) {
        SpringResourceTemplateResolver templateResolver = baseHtmlTemplateResolver(context);
        templateResolver.setPrefix("classpath:/templates/mail/");
        return templateResolver;
    }

    @Bean
    @Primary
    public org.springframework.web.servlet.view.ContentNegotiatingViewResolver viewResolver(ApplicationContext context,
                                                                                            ContentNegotiationManager contentNegotiationManager) {
        ContentNegotiatingViewResolver resolver = new ContentNegotiatingViewResolver();
        ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();

        viewResolver.setCharacterEncoding(StandardCharsets.UTF_8.toString());
        viewResolver.setTemplateEngine(webTemplateEngine(context));
        ForwardAwareInternalResourceViewResolver forwardAwareInternalResourceViewResolver = new ForwardAwareInternalResourceViewResolver();
        BeanNameViewResolver beanNameViewResolver = new BeanNameViewResolver();
        resolver.setViewResolvers(Arrays.asList(viewResolver, forwardAwareInternalResourceViewResolver, beanNameViewResolver));

        MappingJackson2JsonView jackson2JsonView = new MappingJackson2JsonView();
        jackson2JsonView.setExtractValueFromSingleKeyModel(true);
        resolver.setDefaultViews(Arrays.asList(jackson2JsonView));

        resolver.setContentNegotiationManager(contentNegotiationManager);
        return resolver;
    }

    private SpringResourceTemplateResolver baseHtmlTemplateResolver(ApplicationContext context) {
        SpringResourceTemplateResolver templateResolver = new SpringResourceTemplateResolver();
        templateResolver.setSuffix(".html");
        templateResolver.setTemplateMode("HTML5");
        templateResolver.setApplicationContext(context);
        return templateResolver;
    }

    @Bean
    @Primary
    public RequestMappingHandlerMapping requestMappingHandlerMapping(){

        RequestMappingHandlerMapping requestMappingHandlerMapping = new RequestMappingHandlerMapping();

        requestMappingHandlerMapping.setContentNegotiationManager(contentNegotiationManager().getObject());

        requestMappingHandlerMapping.setUseSuffixPatternMatch(false);

        requestMappingHandlerMapping.setOrder(1);

        return requestMappingHandlerMapping;

    }


    @Bean
    @Primary
    public ContentNegotiationManagerFactoryBean contentNegotiationManager(){

        ContentNegotiationManagerFactoryBean contentNegotiationManager = new ContentNegotiationManagerFactoryBean();
        contentNegotiationManager.setFavorPathExtension(false);
        contentNegotiationManager.setFavorParameter(true);
        Map<String, MediaType> mediaTypes = new HashMap<String, MediaType>();
        mediaTypes.put("json",MediaType.APPLICATION_JSON);
        mediaTypes.put("json",MediaType.APPLICATION_XML);
        mediaTypes.put("json",MediaType.TEXT_HTML);
        contentNegotiationManager.addMediaTypes(mediaTypes);
        return contentNegotiationManager;
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/resources/**").addResourceLocations("classpath:/resources/");
        registry.addResourceHandler("/vendor/**").addResourceLocations("classpath:/vendor/");
    }
}
