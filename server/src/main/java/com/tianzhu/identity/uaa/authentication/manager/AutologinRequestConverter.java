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
package com.tianzhu.identity.uaa.authentication.manager;

import com.fasterxml.jackson.core.type.TypeReference;
import com.tianzhu.identity.uaa.login.AutologinRequest;
import com.tianzhu.identity.uaa.util.JsonUtils;
import com.tianzhu.identity.uaa.util.LinkedMaskingMultiValueMap;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.*;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class AutologinRequestConverter extends AbstractHttpMessageConverter<AutologinRequest> {

    private FormHttpMessageConverter formConverter = new FormHttpMessageConverter();
    private StringHttpMessageConverter stringConverter = new StringHttpMessageConverter();

    public AutologinRequestConverter() {
        setSupportedMediaTypes(Arrays.asList(
            MediaType.APPLICATION_FORM_URLENCODED,
            MediaType.APPLICATION_JSON)
        );
    }

    @Override
    protected boolean supports(Class<?> clazz) {
        return AutologinRequest.class.isAssignableFrom(clazz);
    }

    public boolean isJsonContent(List<String> contentType) {
        if (contentType != null) {
            for (String s : contentType) {
                if (s!=null && s.contains(MediaType.APPLICATION_JSON_VALUE)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    protected AutologinRequest readInternal(Class<? extends AutologinRequest> clazz, HttpInputMessage inputMessage)
                    throws IOException, HttpMessageNotReadableException {

        String username, password;
        if (isJsonContent(inputMessage.getHeaders().get(HttpHeaders.CONTENT_TYPE))) {
            Map<String, String> map = JsonUtils.readValue(stringConverter.read(String.class, inputMessage),
                                                          new TypeReference<Map<String, String>>() {});
            username = map.get("username");
            password = map.get("password");
        } else {
            MultiValueMap<String, String> map = formConverter.read(null, inputMessage);
            username = map.getFirst("username");
            password = map.getFirst("password");
        }
        AutologinRequest result = new AutologinRequest();
        result.setUsername(username);
        result.setPassword(password);
        return result;
    }

    @Override
    protected void writeInternal(AutologinRequest t, HttpOutputMessage outputMessage) throws IOException,
            HttpMessageNotWritableException {
        MultiValueMap<String, String> map = new LinkedMaskingMultiValueMap<String, String>("password");
        if (t.getUsername() != null) {
            map.set("username", t.getUsername());
        }
        if (t.getPassword() != null) {
            map.set("password", t.getPassword());
        }
        formConverter.write(map, MediaType.APPLICATION_FORM_URLENCODED, outputMessage);
    }
}