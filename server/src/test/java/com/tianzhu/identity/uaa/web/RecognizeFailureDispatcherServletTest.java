/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package com.tianzhu.identity.uaa.web;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.DispatcherServlet;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletResponse;
import java.sql.SQLException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.*;

public class RecognizeFailureDispatcherServletTest {


    private MockHttpServletRequest request;
    private RecognizeFailureDispatcherServlet servlet;
    private MockHttpServletResponse response;
    private DispatcherServlet delegate;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        servlet = new RecognizeFailureDispatcherServlet();
        response = new MockHttpServletResponse();
        delegate = mock(DispatcherServlet.class);
    }

    @Test
    public void service_when_failure() throws Exception {
        Mockito.doThrow(new RuntimeException("some app error", new SQLException("db error"))).when(delegate).init(ArgumentMatchers.anyObject());
        servlet.setDelegate(delegate);
        servlet.init(mock(ServletConfig.class));
        servlet.service(request, response);
        assertEquals(HttpServletResponse.SC_SERVICE_UNAVAILABLE, response.getStatus());
        verify(delegate, times(1)).init(ArgumentMatchers.anyObject());
        verify(delegate, times(0)).service(ArgumentMatchers.anyObject(), ArgumentMatchers.anyObject());
        assertNotNull(response.getHeader(RecognizeFailureDispatcherServlet.HEADER));
        assertEquals(RecognizeFailureDispatcherServlet.HEADER_MSG, response.getHeader(RecognizeFailureDispatcherServlet.HEADER));
    }
    @Test
    public void service_when_ok() throws Exception {
        DispatcherServlet delegate = mock(DispatcherServlet.class);
        Mockito.doNothing().when(delegate).init(ArgumentMatchers.anyObject());
        servlet.setDelegate(delegate);
        servlet.init(mock(ServletConfig.class));
        servlet.service(request, response);
        verify(delegate, times(1)).init(ArgumentMatchers.anyObject());
        verify(delegate, times(1)).service(ArgumentMatchers.anyObject(), ArgumentMatchers.anyObject());
    }


}