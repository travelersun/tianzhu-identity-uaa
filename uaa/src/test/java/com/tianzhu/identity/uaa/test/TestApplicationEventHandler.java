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
package com.tianzhu.identity.uaa.test;

import org.springframework.context.ApplicationEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class TestApplicationEventHandler<T extends ApplicationEvent> {
    protected final List<T> events = new ArrayList<T>();
    protected final Class<T> clazz;

    public TestApplicationEventHandler(Class<T> eventType) {
        this.clazz = eventType;
    }

    public int getEventCount() {
        return events.size();
    }

    public void clearEvents() {
        events.clear();
    }

    public List<T> getEvents() {
        return Collections.unmodifiableList(events);
    }

    public T getEarliestEvent() {
        if (events.size() > 0) {
            return events.get(0);
        } else {
            return null;
        }
    }

    public T getLatestEvent() {
        if (events.size() > 0) {
            return events.get(events.size() - 1);
        } else {
            return null;
        }
    }

    protected void handleEvent(ApplicationEvent applicationEvent) {
        if (clazz.isAssignableFrom(applicationEvent.getClass())) {
            events.add((T) applicationEvent);
        }
    }
}
