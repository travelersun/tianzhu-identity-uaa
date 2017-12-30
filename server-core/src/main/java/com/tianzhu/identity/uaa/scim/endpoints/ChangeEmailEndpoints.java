package com.tianzhu.identity.uaa.scim.endpoints;

import com.fasterxml.jackson.core.type.TypeReference;
import com.tianzhu.identity.uaa.account.EmailChange;
import com.tianzhu.identity.uaa.account.EmailChangeResponse;
import com.tianzhu.identity.uaa.codestore.ExpiringCode;
import com.tianzhu.identity.uaa.codestore.ExpiringCodeStore;
import com.tianzhu.identity.uaa.constants.OriginKeys;
import com.tianzhu.identity.uaa.error.UaaException;
import com.tianzhu.identity.uaa.resources.QueryableResourceManager;
import com.tianzhu.identity.uaa.scim.ScimUser;
import com.tianzhu.identity.uaa.scim.ScimUserProvisioning;
import com.tianzhu.identity.uaa.scim.event.UserModifiedEvent;
import com.tianzhu.identity.uaa.util.JsonUtils;
import com.tianzhu.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.List;
import java.util.Map;

import static com.tianzhu.identity.uaa.codestore.ExpiringCodeType.EMAIL;
import static org.springframework.http.HttpStatus.*;

@Controller
public class ChangeEmailEndpoints implements ApplicationEventPublisherAware {
    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore expiringCodeStore;
    private ApplicationEventPublisher publisher;
    private final QueryableResourceManager<ClientDetails> clientDetailsService;
    private static final int EMAIL_CHANGE_LIFETIME = 30 * 60 * 1000;

    public static final String CHANGE_EMAIL_REDIRECT_URL = "change_email_redirect_url";

    @Autowired
    public ChangeEmailEndpoints(@Qualifier("scimUserProvisioning") ScimUserProvisioning scimUserProvisioning, @Qualifier("codeStore") ExpiringCodeStore expiringCodeStore, @Qualifier("clientDetailsService") QueryableResourceManager<ClientDetails> clientDetailsService) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.expiringCodeStore = expiringCodeStore;
        this.clientDetailsService = clientDetailsService;
    }

    @RequestMapping(value="/email_verifications", method = RequestMethod.POST)
    public ResponseEntity<String> generateEmailVerificationCode(@RequestBody EmailChange emailChange) {
        String userId = emailChange.getUserId();
        String email = emailChange.getEmail();

        ScimUser user = scimUserProvisioning.retrieve(userId, IdentityZoneHolder.get().getId());
        if (user.getUserName().equals(user.getPrimaryEmail())) {
            List<ScimUser> results = scimUserProvisioning.query("userName eq \"" + email + "\" and origin eq \"" + OriginKeys.UAA + "\"", IdentityZoneHolder.get().getId());
            if (!results.isEmpty()) {
                    return new ResponseEntity<>(CONFLICT);
            }
        }

        String code;
        try {
            code = expiringCodeStore.generateCode(JsonUtils.writeValueAsString(emailChange), new Timestamp(System.currentTimeMillis() + EMAIL_CHANGE_LIFETIME), EMAIL.name(), IdentityZoneHolder.get().getId()).getCode();
        } catch (JsonUtils.JsonUtilException e) {
            throw new UaaException("Error while generating change email code", e);
        }

        return new ResponseEntity<>(code, CREATED);
    }

    @RequestMapping(value="/email_changes", method = RequestMethod.POST)
    public ResponseEntity<EmailChangeResponse> changeEmail(@RequestBody String code) throws IOException {
        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code, IdentityZoneHolder.get().getId());
        if ((null != expiringCode) && ((null == expiringCode.getIntent()) || EMAIL.name().equals(expiringCode.getIntent()))) {
            Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
            String userId = data.get("userId");
            String email = data.get("email");
            ScimUser user = scimUserProvisioning.retrieve(userId, IdentityZoneHolder.get().getId());
            if (user.getUserName().equals(user.getPrimaryEmail())) {
                user.setUserName(email);
            }
            user.setPrimaryEmail(email);

            scimUserProvisioning.update(userId, user, IdentityZoneHolder.get().getId());

            String redirectLocation = null;
            String clientId = data.get("client_id");

            if (clientId != null && !clientId.equals("")) {
                ClientDetails clientDetails = clientDetailsService.retrieve(clientId, IdentityZoneHolder.get().getId());
                redirectLocation = (String) clientDetails.getAdditionalInformation().get(CHANGE_EMAIL_REDIRECT_URL);
            }

            publisher.publishEvent(UserModifiedEvent.emailChanged(userId, user.getUserName(), user.getPrimaryEmail()));

            EmailChangeResponse emailChangeResponse = new EmailChangeResponse();
            emailChangeResponse.setEmail(email);
            emailChangeResponse.setUserId(userId);
            emailChangeResponse.setUsername(user.getUserName());
            emailChangeResponse.setRedirectUrl(redirectLocation);
            return new ResponseEntity<>(emailChangeResponse, OK);
        } else {
            return new ResponseEntity<>(UNPROCESSABLE_ENTITY);
        }
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

}
