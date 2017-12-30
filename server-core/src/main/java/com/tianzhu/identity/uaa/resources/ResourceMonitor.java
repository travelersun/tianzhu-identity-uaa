package com.tianzhu.identity.uaa.resources;


public interface ResourceMonitor<T> {
    /** 
     * Returns the total number of things in the underlying store
     * @return
     */
    int getTotalCount();
}
