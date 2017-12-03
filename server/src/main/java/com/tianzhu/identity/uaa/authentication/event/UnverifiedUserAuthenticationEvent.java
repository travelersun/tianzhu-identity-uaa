package com.tianzhu.identity.uaa.authentication.event;

import com.tianzhu.identity.uaa.audit.AuditEvent;
import com.tianzhu.identity.uaa.audit.AuditEventType;
import com.tianzhu.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

public class UnverifiedUserAuthenticationEvent extends AbstractUaaAuthenticationEvent {

    private final UaaUser user;

    public UnverifiedUserAuthenticationEvent(UaaUser user, Authentication authentication) {
        super(authentication);
        Assert.notNull(user, "UaaUser object cannot be null");
        this.user = user;
    }

    @Override
    public AuditEvent getAuditEvent() {
        return createAuditRecord(user.getId(), AuditEventType.UnverifiedUserAuthentication, getOrigin(getAuthenticationDetails()),
                user.getUsername());
    }

    public UaaUser getUser() {
        return user;
    }
}
