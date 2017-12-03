package com.tianzhu.identity.uaa.web;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.MockHttpOutputMessage;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;

public class ExceptionReportHttpMessageConverterTest {

    private ExceptionReportHttpMessageConverter exceptionReportHttpMessageConverter;
    private HttpMessageConverter httpMessageConverter;
    private HttpOutputMessage httpOutputMessage;

    @Before
    public void setUp() throws Exception {
        exceptionReportHttpMessageConverter = new ExceptionReportHttpMessageConverter();

        httpMessageConverter = mock(HttpMessageConverter.class);
        httpOutputMessage = new MockHttpOutputMessage();
        exceptionReportHttpMessageConverter.setMessageConverters(
            new HttpMessageConverter<?>[]{httpMessageConverter});

        when(httpMessageConverter.canWrite(ArgumentMatchers.any(Class.class), ArgumentMatchers.any(MediaType.class))).thenReturn(true);
        when(httpMessageConverter.getSupportedMediaTypes()).thenReturn(Arrays.asList(APPLICATION_JSON));
    }

    @Test
    public void testWriteInternal() throws Exception {
        ExceptionReport report = new ExceptionReport(new Exception("oh noes!"));

        exceptionReportHttpMessageConverter.writeInternal(report, httpOutputMessage);

        Map<String, String> expectedFields = new HashMap<>();
        expectedFields.put("error", "exception");
        expectedFields.put("message", "oh noes!");
        expectedFields.put("error_description", "oh noes!");
        verify(httpMessageConverter).write(ArgumentMatchers.eq(expectedFields), ArgumentMatchers.eq(APPLICATION_JSON), ArgumentMatchers.eq(httpOutputMessage));
    }

    @Test
    public void testWriteInteralWithExtraInfo() throws Exception {
        Map<String, Object> extraInfo = new HashMap<>();
        extraInfo.put("user_id", "cba09242-aa43-4247-9aa0-b5c75c281f94");
        extraInfo.put("active", true);
        extraInfo.put("verified", false);
        ExceptionReport report = new ExceptionReport(new Exception("oh noes!"), false, extraInfo);
        exceptionReportHttpMessageConverter.writeInternal(report, httpOutputMessage);

        Map<String, Object> expectedFields = new HashMap<>();
        expectedFields.put("error", "exception");
        expectedFields.put("message", "oh noes!");
        expectedFields.put("error_description", "oh noes!");
        expectedFields.putAll(extraInfo);
        verify(httpMessageConverter).write(ArgumentMatchers.eq(expectedFields), ArgumentMatchers.eq(APPLICATION_JSON), ArgumentMatchers.eq(httpOutputMessage));

    }
}