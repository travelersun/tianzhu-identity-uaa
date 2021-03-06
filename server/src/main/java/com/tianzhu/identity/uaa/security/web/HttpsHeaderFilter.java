/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package com.tianzhu.identity.uaa.security.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class HttpsHeaderFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(HttpsHeaderFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        FixHttpsSchemeRequest modifiedRequest = new FixHttpsSchemeRequest((HttpServletRequest) request);
        chain.doFilter(modifiedRequest, response);
    }

    @Override
    public void init(FilterConfig arg0) throws ServletException {
        logger.info("Filter inited");
    }

    @Override
    public void destroy() {
    }

}
