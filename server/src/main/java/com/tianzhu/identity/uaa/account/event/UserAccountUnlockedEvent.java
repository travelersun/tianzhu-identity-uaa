package com.tianzhu.identity.uaa.account.event;

import com.tianzhu.identity.uaa.audit.AuditEvent;
import com.tianzhu.identity.uaa.audit.AuditEventType;
import com.tianzhu.identity.uaa.audit.event.AbstractUaaEvent;
import com.tianzhu.identity.uaa.scim.ScimUser;

public class UserAccountUnlockedEvent extends AbstractUaaEvent {
  public UserAccountUnlockedEvent(ScimUser user) {
    super(user);
  }

  @Override
  public AuditEvent getAuditEvent() {
    return createAuditRecord(((ScimUser)source).getId(), AuditEventType.UserAccountUnlockedEvent, ((ScimUser)source).getOrigin());
  }
}
