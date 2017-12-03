/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  *******************************************************************************
 */

package com.tianzhu.identity.uaa.cache;

import com.tianzhu.identity.uaa.util.TimeService;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;


public class ExpiringUrlCacheTests {

    public static final int EXPIRING_TIME_MILLIS = 10 * 60 * 1000;
    private ExpiringUrlCache cache;
    private TimeService ticker;
    private RestTemplate template;
    private String uri;
    private byte[] content = new byte[1024];

    @Before
    public void setup() {
        Arrays.fill(content, (byte) 1);
        ticker = mock(TimeService.class);
        when(ticker.getCurrentTimeMillis()).thenAnswer(e -> System.currentTimeMillis());
        cache = new ExpiringUrlCache(EXPIRING_TIME_MILLIS, ticker, 2);
        template = mock(RestTemplate.class);
        when(template.getForObject(ArgumentMatchers.any(URI.class), ArgumentMatchers.any())).thenReturn(content, new byte[1024]);
        uri = "http://localhost:8080/uaa/.well-known/openid-configuration";
    }

    @Test
    public void correct_method_invoked_on_rest_template() throws URISyntaxException {
        cache.getUrlContent(uri, template);
        verify(template, times(1)).getForObject(ArgumentMatchers.eq(new URI(uri)), ArgumentMatchers.same((new byte[0]).getClass()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void incorrect_uri_throws_illegal_argument_exception() {
        uri = "invalid value";
        cache.getUrlContent(uri, template);
    }

    @Test
    public void rest_client_exception_returns_null() {
        template = mock(RestTemplate.class);
        when(template.getForObject(ArgumentMatchers.any(URI.class), ArgumentMatchers.any())).thenThrow(new RestClientException("mock"));
        assertNull(cache.getUrlContent(uri, template));
        assertEquals(0, cache.size());
    }

    @Test
    public void calling_twice_uses_cache() throws Exception {
        byte[] c1 = cache.getUrlContent(uri, template);
        byte[] c2 = cache.getUrlContent(uri, template);
        verify(template, times(1)).getForObject(ArgumentMatchers.eq(new URI(uri)), ArgumentMatchers.same((new byte[0]).getClass()));
        assertSame(c1, c2);
        assertEquals(1, cache.size());
    }

    @Test
    public void entry_expires_on_time() throws Exception {
        when(ticker.getCurrentTimeMillis()).thenReturn(System.currentTimeMillis(), System.currentTimeMillis() + EXPIRING_TIME_MILLIS + 10000);
        byte[] c1 = cache.getUrlContent(uri, template);
        byte[] c2 = cache.getUrlContent(uri, template);
        verify(template, times(2)).getForObject(ArgumentMatchers.eq(new URI(uri)), ArgumentMatchers.same((new byte[0]).getClass()));
        assertNotSame(c1, c2);
    }


    //@Test
    public void test_google_returns_same_array() {
        uri = "https://accounts.google.com/.well-known/openid-configuration";
        byte[] c1 = cache.getUrlContent(uri, new RestTemplate());
        byte[] c2 = cache.getUrlContent(uri, new RestTemplate());
        assertNotNull(c1);
        assertSame(c1, c2);
    }

    @Test
    public void cache_should_start_empty() {
        assertEquals(0, cache.size());
    }

    @Test
    public void max_entries_is_respected() throws URISyntaxException {
        String uri1 = "http://test1.com";
        String uri2 = "http://test2.com";
        String uri3 = "http://test3.com";
        byte[] c1 = new byte[1024];
        byte[] c2 = new byte[1024];
        byte[] c3 = new byte[1024];
        template = mock(RestTemplate.class);
        when(template.getForObject(ArgumentMatchers.eq(new URI(uri1)), ArgumentMatchers.any())).thenReturn(c1);
        when(template.getForObject(ArgumentMatchers.eq(new URI(uri2)), ArgumentMatchers.any())).thenReturn(c2);
        when(template.getForObject(ArgumentMatchers.eq(new URI(uri3)), ArgumentMatchers.any())).thenReturn(c3);
        for (String uri : Arrays.asList(uri1, uri1, uri2, uri2, uri3, uri3)) {
            cache.getUrlContent(uri, template);
        }
        for (String uri : Arrays.asList(uri1, uri2, uri3)) {
            verify(template, times(1)).getForObject(ArgumentMatchers.eq(new URI(uri)), ArgumentMatchers.same((new byte[0]).getClass()));
        }
        assertEquals(2, cache.size());
    }


}
