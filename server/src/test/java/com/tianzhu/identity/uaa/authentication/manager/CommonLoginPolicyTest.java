package com.tianzhu.identity.uaa.authentication.manager;

import com.tianzhu.identity.uaa.audit.AuditEvent;
import com.tianzhu.identity.uaa.audit.AuditEventType;
import com.tianzhu.identity.uaa.audit.UaaAuditService;
import com.tianzhu.identity.uaa.provider.LockoutPolicy;
import com.tianzhu.identity.uaa.util.TimeService;
import com.tianzhu.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class CommonLoginPolicyTest {
    private CommonLoginPolicy commonLoginPolicy;
    private LockoutPolicyRetriever lockoutPolicyRetriever;
    private TimeService timeService;
    private UaaAuditService auditService;
    private AuditEventType failureEventType;
    private AuditEventType successEventType;
    private boolean enabled = true;

    @Before
    public void setup() {
        auditService = mock(UaaAuditService.class);
        timeService = mock(TimeService.class);
        lockoutPolicyRetriever = mock(LockoutPolicyRetriever.class);
        successEventType = AuditEventType.UserAuthenticationSuccess;
        failureEventType = AuditEventType.UserAuthenticationFailure;

        commonLoginPolicy = new CommonLoginPolicy(auditService, lockoutPolicyRetriever, successEventType, failureEventType, timeService, enabled);
    }

    @Test
    public void test_is_disabled() throws Exception {
        commonLoginPolicy = spy(new CommonLoginPolicy(auditService, lockoutPolicyRetriever, successEventType, failureEventType, timeService, false));
        LoginPolicy.Result result = commonLoginPolicy.isAllowed("principal");
        assertTrue(result.isAllowed());
        assertEquals(0, result.getFailureCount());
        verifyZeroInteractions(lockoutPolicyRetriever);
        verifyZeroInteractions(timeService);
        verifyZeroInteractions(auditService);
    }

    @Test
    public void isAllowed_whenLockoutAfterFailuresIsNegative_returnsTrue() {
        when(lockoutPolicyRetriever.getLockoutPolicy()).thenReturn(new LockoutPolicy(-1, -1, 300));

        LoginPolicy.Result result = commonLoginPolicy.isAllowed("principal");

        assertTrue(result.isAllowed());
        assertEquals(0, result.getFailureCount());
    }

    @Test
    public void isAllowed_whenLockoutAfterFailuresIsPositive_returnsFalseIfTooManyFailedRecentAttempts() {
        when(lockoutPolicyRetriever.getLockoutPolicy()).thenReturn(new LockoutPolicy(2, 1, 300));
        AuditEvent auditEvent = new AuditEvent(failureEventType, null, null, null, 1L, null);
        List<AuditEvent> list = Arrays.asList(auditEvent);
        String zoneId = IdentityZoneHolder.get().getId();
        when(auditService.find(ArgumentMatchers.eq("principal"), ArgumentMatchers.anyLong(), ArgumentMatchers.eq(zoneId))).thenReturn(list);

        LoginPolicy.Result result = commonLoginPolicy.isAllowed("principal");

        assertFalse(result.isAllowed());
        assertEquals(1, result.getFailureCount());
    }

    @Test
    public void isAllowed_whenLockoutAfterFailuresIsPositive_returnsTrueIfNotTooManyFailedRecentAttempts() {
        when(lockoutPolicyRetriever.getLockoutPolicy()).thenReturn(new LockoutPolicy(2, 2, 300));
        AuditEvent auditEvent = new AuditEvent(failureEventType, null, null, null, 1L, null);
        List<AuditEvent> list = Arrays.asList(auditEvent);
        String zoneId = IdentityZoneHolder.get().getId();
        when(auditService.find(ArgumentMatchers.eq("principal"), ArgumentMatchers.anyLong(), ArgumentMatchers.eq(zoneId))).thenReturn(list);

        LoginPolicy.Result result = commonLoginPolicy.isAllowed("principal");

        assertTrue(result.isAllowed());
        assertEquals(1, result.getFailureCount());
    }
}
