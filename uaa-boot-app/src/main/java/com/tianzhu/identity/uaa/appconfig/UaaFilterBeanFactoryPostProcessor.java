package com.tianzhu.identity.uaa.appconfig;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

import java.util.Iterator;

/**
 * Created by gzcss on 2017/12/13.
 */
//@Configuration
//@Order(Ordered.HIGHEST_PRECEDENCE)
public class UaaFilterBeanFactoryPostProcessor implements BeanFactoryPostProcessor {

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory configurableListableBeanFactory) throws BeansException {

        Iterator l = configurableListableBeanFactory.getBeanNamesIterator();

        for (Iterator iter = l; iter.hasNext();) {
            String str = (String)iter.next();//FilterRegistrationBean
            BeanDefinition bdefine=configurableListableBeanFactory.getBeanDefinition(str);
            String cname = bdefine.getBeanClassName();
            System.out.println(str+":"+cname);
        }


    }
}
