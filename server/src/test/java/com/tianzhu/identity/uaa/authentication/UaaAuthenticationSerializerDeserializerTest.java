package com.tianzhu.identity.uaa.authentication;

import com.tianzhu.identity.uaa.constants.OriginKeys;
import com.tianzhu.identity.uaa.user.UaaAuthority;
import com.tianzhu.identity.uaa.util.JsonUtils;
import com.tianzhu.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Test;

import java.util.Collections;
import java.util.LinkedList;

import static org.junit.Assert.assertEquals;

public class UaaAuthenticationSerializerDeserializerTest {

    @Test
    public void serializeUaaAuthentication() throws Exception {
        UaaPrincipal p = new UaaPrincipal("user-id", "username", "user@example.com", OriginKeys.UAA, "", IdentityZoneHolder.get().getId());
        UaaAuthentication auth = new UaaAuthentication(p, UaaAuthority.USER_AUTHORITIES, new UaaAuthenticationDetails(false, "clientId", OriginKeys.ORIGIN,"sessionId"));
        auth.setAuthenticationMethods(Collections.singleton("pwd"));
        auth.setAuthContextClassRef(Collections.singleton("test:uri"));
        auth.setLastLoginSuccessTime(1485305759366l);

        UaaAuthentication deserializedUaaAuthentication = JsonUtils.readValue(JsonUtils.writeValueAsString(auth), UaaAuthentication.class);

        assertEquals(auth.getDetails(), deserializedUaaAuthentication.getDetails());
        assertEquals(auth.getPrincipal(), deserializedUaaAuthentication.getPrincipal());
        assertEquals("uaa.user", ((LinkedList) deserializedUaaAuthentication.getAuthorities()).get(0).toString());
        assertEquals(Collections.EMPTY_SET, deserializedUaaAuthentication.getExternalGroups());
        assertEquals(auth.getExpiresAt(), deserializedUaaAuthentication.getExpiresAt());
        assertEquals(auth.getAuthenticatedTime(), deserializedUaaAuthentication.getAuthenticatedTime());
        assertEquals(auth.isAuthenticated(), deserializedUaaAuthentication.isAuthenticated());
        assertEquals(auth.getUserAttributesAsMap(), deserializedUaaAuthentication.getUserAttributesAsMap());
        assertEquals(auth.getAuthenticationMethods(), deserializedUaaAuthentication.getAuthenticationMethods());
        assertEquals(auth.getAuthContextClassRef(), deserializedUaaAuthentication.getAuthContextClassRef());
        assertEquals(auth.getLastLoginSuccessTime(), deserializedUaaAuthentication.getLastLoginSuccessTime());
    }
}
