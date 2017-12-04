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
package com.tianzhu.identity.uaa.scim.endpoints;

import com.tianzhu.identity.uaa.test.SnippetUtils;
import org.apache.commons.lang3.ArrayUtils;
import com.tianzhu.identity.uaa.account.PasswordChangeRequest;
import com.tianzhu.identity.uaa.account.UserAccountStatus;
import com.tianzhu.identity.uaa.approval.Approval;
import com.tianzhu.identity.uaa.approval.ApprovalStore;
import com.tianzhu.identity.uaa.constants.OriginKeys;
import com.tianzhu.identity.uaa.mock.InjectedMockContextTest;
import com.tianzhu.identity.uaa.mock.util.MockMvcUtils;
import com.tianzhu.identity.uaa.scim.ScimUser;
import com.tianzhu.identity.uaa.scim.ScimUserProvisioning;
import com.tianzhu.identity.uaa.user.UaaUserDatabase;
import com.tianzhu.identity.uaa.util.JsonUtils;
import com.tianzhu.identity.uaa.zone.IdentityZoneHolder;
import com.tianzhu.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.restdocs.headers.HeaderDescriptor;
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.payload.PayloadDocumentation;
import org.springframework.restdocs.request.ParameterDescriptor;
import org.springframework.restdocs.request.RequestDocumentation;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Collections;
import java.util.Date;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessRequest;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.ARRAY;
import static org.springframework.restdocs.payload.JsonFieldType.BOOLEAN;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.OBJECT;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ScimUserEndpointDocs extends InjectedMockContextTest {

    private final String startIndexDescription = "The starting index of the search results when paginated. Index starts with 1.";
    private final String countAndItemsPerPageDescription = "The maximum number of items returned per request.";
    private final String totalResultsDescription = "Number of results in result set.";

    private final String userIdDescription = "Unique user identifier.";
    private final String resourceDescription = "A list of SCIM user objects retrieved by the search.";
    private final String usernameDescription = "User name of the user, typically an email address.";
    private final String nameObjectDescription = "A map with the user's first name and last name.";
    private final String lastnameDescription = "The user's last name.";
    private final String firstnameDescription = "The user's first name.";
    private final String emailListDescription = "The user's email addresses.";
    private final String emailDescription = "The email address.";
    private final String emailPrimaryDescription = "Set to true if this is the user's primary email address.";
    private final String groupDescription = "A list of groups the user belongs to.";

    private final String schemasDescription = "SCIM Schemas used, currently always set to [ \"urn:scim:schemas:core:1.0\" ]";
    private final String groupIdDescription = "Unique group identifier";
    private final String groupDisplayNameDescription = "The group display name, also referred to as scope during authorization.";
    private final String membershipTypeDescription = "Membership type - DIRECT means the user is directly associated with the group. INDIRECT means that the membership has been inherited from nested groups.";
    private final String approvalsListDescription = "A list of approvals for this user. Approvals are user's explicit approval or rejection for an application.";
    private final String approvalUserIdDescription = "The user id on the approval. Will be the same as the id field.";
    private final String approvalClientIdDescription = "The client id on the approval. Represents the application this approval or denial was for.";
    private final String approvalScopeDescription = "The scope on the approval. Will be a group display value.";
    private final String approvalStatusDescription = "The status of the approval. APPROVED or DENIED are the only valid values.";
    private final String approvalsLastUpdatedAtDescription = "Date this approval was last updated.";
    private final String approvalsExpiresAtDescription = "Date this approval will expire.";
    private final String userActiveDescription = "If this user is active. False is a soft delete. The user will not be able to log in.";
    private final String userVerifiedDescription = "True, if this user has verified her/his email address.";
    private final String userOriginDescription = "The alias of the identity provider that authenticated this user. 'uaa' is an internal UAA user.";
    private final String userZoneIdDescription = "The zone this user belongs to. 'uaa' is the default zone.";
    private final String passwordLastModifiedDescription = "The timestamp this user's password was last changed.";
    private final String externalIdDescription = "External user ID if authenticated through external identity provider.";
    private final String passwordDescription = "User's password, required if origin is set to 'uaa'.";
    private final String phoneNumbersListDescription = "The user's phone numbers.";
    private final String phoneNumbersDescription = "The phone number.";

    private final String metaDesc = "SCIM object meta data.";
    private final String metaVersionDesc = "Object version.";
    private final String metaLastModifiedDesc = "Object last modified date.";
    private final String metaCreatedDesc = "Object created date.";
    private final String metaAttributesDesc = "Names of attributes that shall be deleted";
    private final String userLastLogonTimeDescription = "The unix epoch timestamp of when the user last authenticated. Default value of this field is null and is omitted from the response if null";
    private final String userPreviousLogonTimeDescription = "The unix epoch timestamp of 2nd to last successful user authentication. Default value of this field is null and is omitted from the response if null";

    FieldDescriptor[] searchResponseFields = {
        SnippetUtils.fieldWithPath("startIndex").type(NUMBER).description(startIndexDescription),
        SnippetUtils.fieldWithPath("itemsPerPage").type(NUMBER).description(countAndItemsPerPageDescription),
        SnippetUtils.fieldWithPath("totalResults").type(NUMBER).description(totalResultsDescription),
        SnippetUtils.fieldWithPath("schemas").type(ARRAY).description(schemasDescription),
        SnippetUtils.fieldWithPath("resources").type(ARRAY).description(resourceDescription),
        SnippetUtils.fieldWithPath("resources[].schemas").type(ARRAY).description(schemasDescription),
        SnippetUtils.fieldWithPath("resources[].id").type(STRING).description(userIdDescription),
        SnippetUtils.fieldWithPath("resources[].userName").type(STRING).description(usernameDescription),
        SnippetUtils.fieldWithPath("resources[].name").type(OBJECT).description(nameObjectDescription),
        SnippetUtils.fieldWithPath("resources[].name.familyName").type(STRING).description(lastnameDescription),
        SnippetUtils.fieldWithPath("resources[].name.givenName").type(STRING).description(firstnameDescription),
        SnippetUtils.fieldWithPath("resources[].phoneNumbers").type(ARRAY).description(phoneNumbersListDescription),
        SnippetUtils.fieldWithPath("resources[].phoneNumbers[].value").type(STRING).description(phoneNumbersDescription),
        SnippetUtils.fieldWithPath("resources[].emails").type(ARRAY).description(emailListDescription),
        SnippetUtils.fieldWithPath("resources[].emails[].value").type(STRING).description(emailDescription),
        SnippetUtils.fieldWithPath("resources[].emails[].primary").type(BOOLEAN).description(emailPrimaryDescription),
        SnippetUtils.fieldWithPath("resources[].groups").type(ARRAY).description(groupDescription),
        SnippetUtils.fieldWithPath("resources[].groups[].value").type(STRING).description(groupIdDescription),
        SnippetUtils.fieldWithPath("resources[].groups[].display").type(STRING).description(groupDisplayNameDescription),
        SnippetUtils.fieldWithPath("resources[].groups[].type").type(STRING).description(membershipTypeDescription),
        SnippetUtils.fieldWithPath("resources[].approvals").type(ARRAY).description(approvalsListDescription),
        SnippetUtils.fieldWithPath("resources[].approvals[].userId").type(STRING).description(approvalUserIdDescription),
        SnippetUtils.fieldWithPath("resources[].approvals[].clientId").type(STRING).description(approvalClientIdDescription),
        SnippetUtils.fieldWithPath("resources[].approvals[].scope").type(STRING).description(approvalScopeDescription),
        SnippetUtils.fieldWithPath("resources[].approvals[].status").type(STRING).description(approvalStatusDescription),
        SnippetUtils.fieldWithPath("resources[].approvals[].lastUpdatedAt").type(STRING).description(approvalsLastUpdatedAtDescription),
        SnippetUtils.fieldWithPath("resources[].approvals[].expiresAt").type(STRING).description(approvalsExpiresAtDescription),
        SnippetUtils.fieldWithPath("resources[].active").type(BOOLEAN).description(userActiveDescription),
        SnippetUtils.fieldWithPath("resources[].lastLogonTime").optional(null).type(NUMBER).description(userLastLogonTimeDescription),
        SnippetUtils.fieldWithPath("resources[].previousLogonTime").optional(null).type(NUMBER).description(userPreviousLogonTimeDescription),
        SnippetUtils.fieldWithPath("resources[].verified").type(BOOLEAN).description(userVerifiedDescription),
        SnippetUtils.fieldWithPath("resources[].origin").type(STRING).description(userOriginDescription),
        SnippetUtils.fieldWithPath("resources[].zoneId").type(STRING).description(userZoneIdDescription),
        SnippetUtils.fieldWithPath("resources[].passwordLastModified").type(STRING).description(passwordLastModifiedDescription),
        SnippetUtils.fieldWithPath("resources[].externalId").type(STRING).description(externalIdDescription),
        SnippetUtils.fieldWithPath("resources[].meta").type(OBJECT).description(metaDesc),
        SnippetUtils.fieldWithPath("resources[].meta.version").type(NUMBER).description(metaVersionDesc),
        SnippetUtils.fieldWithPath("resources[].meta.lastModified").type(STRING).description(metaLastModifiedDesc),
        SnippetUtils.fieldWithPath("resources[].meta.created").type(STRING).description(metaCreatedDesc)
    };

    Snippet createFields = PayloadDocumentation.requestFields(
        SnippetUtils.fieldWithPath("userName").required().type(STRING).description(usernameDescription),
        SnippetUtils.fieldWithPath("password").optional(null).type(STRING).description(passwordDescription),
        SnippetUtils.fieldWithPath("name").required().type(OBJECT).description(nameObjectDescription),
        SnippetUtils.fieldWithPath("name.formatted").ignored().type(STRING).description("First and last name combined"),
        SnippetUtils.fieldWithPath("name.familyName").required().type(STRING).description(lastnameDescription),
        SnippetUtils.fieldWithPath("name.givenName").required().type(STRING).description(firstnameDescription),
        SnippetUtils.fieldWithPath("phoneNumbers").optional(null).type(ARRAY).description(phoneNumbersListDescription),
        SnippetUtils.fieldWithPath("phoneNumbers[].value").optional(null).type(STRING).description(phoneNumbersDescription),
        SnippetUtils.fieldWithPath("emails").required().type(ARRAY).description(emailListDescription),
        SnippetUtils.fieldWithPath("emails[].value").required().type(STRING).description(emailDescription),
        SnippetUtils.fieldWithPath("emails[].primary").required().type(BOOLEAN).description(emailPrimaryDescription),
        SnippetUtils.fieldWithPath("active").optional(true).type(BOOLEAN).description(userActiveDescription),
        SnippetUtils.fieldWithPath("verified").optional(false).type(BOOLEAN).description(userVerifiedDescription),
        SnippetUtils.fieldWithPath("origin").optional(OriginKeys.UAA).type(STRING).description(userOriginDescription),
        SnippetUtils.fieldWithPath("externalId").optional(null).type(STRING).description(externalIdDescription),
        SnippetUtils.fieldWithPath("schemas").optional().ignored().type(ARRAY).description(schemasDescription),
        SnippetUtils.fieldWithPath("meta.*").optional().ignored().type(OBJECT).description("SCIM object meta data not read.")
    );

    FieldDescriptor[] createResponse = {
        SnippetUtils.fieldWithPath("schemas").type(ARRAY).description(schemasDescription),
        SnippetUtils.fieldWithPath("id").type(STRING).description(userIdDescription),
        SnippetUtils.fieldWithPath("userName").type(STRING).description(usernameDescription),
        SnippetUtils.fieldWithPath("name").type(OBJECT).description(nameObjectDescription),
        SnippetUtils.fieldWithPath("name.familyName").type(STRING).description(lastnameDescription),
        SnippetUtils.fieldWithPath("name.givenName").type(STRING).description(firstnameDescription),
        SnippetUtils.fieldWithPath("phoneNumbers").type(ARRAY).description(phoneNumbersListDescription),
        SnippetUtils.fieldWithPath("phoneNumbers[].value").type(STRING).description(phoneNumbersDescription),
        SnippetUtils.fieldWithPath("emails").type(ARRAY).description(emailListDescription),
        SnippetUtils.fieldWithPath("emails[].value").type(STRING).description(emailDescription),
        SnippetUtils.fieldWithPath("emails[].primary").type(BOOLEAN).description(emailPrimaryDescription),
        SnippetUtils.fieldWithPath("groups").type(ARRAY).description(groupDescription),
        SnippetUtils.fieldWithPath("groups[].value").type(STRING).description(groupIdDescription),
        SnippetUtils.fieldWithPath("groups[].display").type(STRING).description(groupDisplayNameDescription),
        SnippetUtils.fieldWithPath("groups[].type").type(STRING).description(membershipTypeDescription),
        SnippetUtils.fieldWithPath("approvals").type(ARRAY).description(approvalsListDescription),
        SnippetUtils.fieldWithPath("active").type(BOOLEAN).description(userActiveDescription),
        SnippetUtils.fieldWithPath("verified").type(BOOLEAN).description(userVerifiedDescription),
        SnippetUtils.fieldWithPath("origin").type(STRING).description(userOriginDescription),
        SnippetUtils.fieldWithPath("zoneId").type(STRING).description(userZoneIdDescription),
        SnippetUtils.fieldWithPath("passwordLastModified").type(STRING).description(passwordLastModifiedDescription),
        SnippetUtils.fieldWithPath("externalId").type(STRING).description(externalIdDescription),
        SnippetUtils.fieldWithPath("meta").type(OBJECT).description(metaDesc),
        SnippetUtils.fieldWithPath("meta.version").type(NUMBER).description(metaVersionDesc),
        SnippetUtils.fieldWithPath("meta.lastModified").type(STRING).description(metaLastModifiedDesc),
        SnippetUtils.fieldWithPath("meta.created").type(STRING).description(metaCreatedDesc)
    };

    Snippet updateFields = PayloadDocumentation.requestFields(
        SnippetUtils.fieldWithPath("schemas").ignored().type(ARRAY).description(schemasDescription),
        SnippetUtils.fieldWithPath("id").ignored().type(STRING).description(userIdDescription),
        SnippetUtils.fieldWithPath("userName").required().type(STRING).description(usernameDescription),
        SnippetUtils.fieldWithPath("name").required().type(OBJECT).description(nameObjectDescription),
        SnippetUtils.fieldWithPath("name.familyName").required().type(STRING).description(lastnameDescription),
        SnippetUtils.fieldWithPath("name.givenName").required().type(STRING).description(firstnameDescription),
        SnippetUtils.fieldWithPath("phoneNumbers").optional(null).type(ARRAY).description(phoneNumbersListDescription),
        SnippetUtils.fieldWithPath("phoneNumbers[].value").optional(null).type(STRING).description(phoneNumbersDescription),
        SnippetUtils.fieldWithPath("emails").required().type(ARRAY).description(emailListDescription),
        SnippetUtils.fieldWithPath("emails[].value").required().type(STRING).description(emailDescription),
        SnippetUtils.fieldWithPath("emails[].primary").required().type(BOOLEAN).description(emailPrimaryDescription),
        SnippetUtils.fieldWithPath("groups").ignored().type(ARRAY).description("Groups are not created at this time."),
        SnippetUtils.fieldWithPath("approvals").ignored().type(ARRAY).description("Approvals are not created at this time"),
        SnippetUtils.fieldWithPath("active").optional(true).type(BOOLEAN).description(userActiveDescription),
        SnippetUtils.fieldWithPath("verified").optional(false).type(BOOLEAN).description(userVerifiedDescription),
        SnippetUtils.fieldWithPath("origin").optional(OriginKeys.UAA).type(STRING).description(userOriginDescription),
        SnippetUtils.fieldWithPath("zoneId").ignored().type(STRING).description(userZoneIdDescription),
        SnippetUtils.fieldWithPath("passwordLastModified").ignored().type(STRING).description(passwordLastModifiedDescription),
        SnippetUtils.fieldWithPath("externalId").optional(null).type(STRING).description(externalIdDescription),
        SnippetUtils.fieldWithPath("meta.*").ignored().type(OBJECT).description("SCIM object meta data not read.")
    );

    FieldDescriptor[] updateResponse = {
        SnippetUtils.fieldWithPath("schemas").type(ARRAY).description(schemasDescription),
        SnippetUtils.fieldWithPath("id").type(STRING).description(userIdDescription),
        SnippetUtils.fieldWithPath("userName").type(STRING).description(usernameDescription),
        SnippetUtils.fieldWithPath("name").type(OBJECT).description(nameObjectDescription),
        SnippetUtils.fieldWithPath("name.familyName").type(STRING).description(lastnameDescription),
        SnippetUtils.fieldWithPath("name.givenName").type(STRING).description(firstnameDescription),
        SnippetUtils.fieldWithPath("phoneNumbers").type(ARRAY).description(phoneNumbersListDescription),
        SnippetUtils.fieldWithPath("phoneNumbers[].value").type(STRING).description(phoneNumbersDescription),
        SnippetUtils.fieldWithPath("emails").type(ARRAY).description(emailListDescription),
        SnippetUtils.fieldWithPath("emails[].value").type(STRING).description(emailDescription),
        SnippetUtils.fieldWithPath("emails[].primary").type(BOOLEAN).description(emailPrimaryDescription),
        SnippetUtils.fieldWithPath("groups").type(ARRAY).description(groupDescription),
        SnippetUtils.fieldWithPath("groups[].value").type(STRING).description(groupIdDescription),
        SnippetUtils.fieldWithPath("groups[].display").type(STRING).description(groupDisplayNameDescription),
        SnippetUtils.fieldWithPath("groups[].type").type(STRING).description(membershipTypeDescription),
        SnippetUtils.fieldWithPath("approvals").type(ARRAY).description(approvalsListDescription),
        SnippetUtils.fieldWithPath("approvals[].userId").type(STRING).description(approvalUserIdDescription),
        SnippetUtils.fieldWithPath("approvals[].clientId").type(STRING).description(approvalClientIdDescription),
        SnippetUtils.fieldWithPath("approvals[].scope").type(STRING).description(approvalScopeDescription),
        SnippetUtils.fieldWithPath("approvals[].status").type(STRING).description(approvalStatusDescription),
        SnippetUtils.fieldWithPath("approvals[].lastUpdatedAt").type(STRING).description(approvalsLastUpdatedAtDescription),
        SnippetUtils.fieldWithPath("approvals[].expiresAt").type(STRING).description(approvalsExpiresAtDescription),
        SnippetUtils.fieldWithPath("active").type(BOOLEAN).description(userActiveDescription),
        SnippetUtils.fieldWithPath("verified").type(BOOLEAN).description(userVerifiedDescription),
        SnippetUtils.fieldWithPath("origin").type(STRING).description(userOriginDescription),
        SnippetUtils.fieldWithPath("zoneId").type(STRING).description(userZoneIdDescription),
        SnippetUtils.fieldWithPath("passwordLastModified").type(STRING).description(passwordLastModifiedDescription),
        SnippetUtils.fieldWithPath("lastLogonTime").optional(null).type(NUMBER).description(userLastLogonTimeDescription),
        SnippetUtils.fieldWithPath("previousLogonTime").optional(null).type(NUMBER).description(userLastLogonTimeDescription),
        SnippetUtils.fieldWithPath("externalId").type(STRING).description(externalIdDescription),
        SnippetUtils.fieldWithPath("meta").type(OBJECT).description(metaDesc),
        SnippetUtils.fieldWithPath("meta.version").type(NUMBER).description(metaVersionDesc),
        SnippetUtils.fieldWithPath("meta.lastModified").type(STRING).description(metaLastModifiedDesc),
        SnippetUtils.fieldWithPath("meta.created").type(STRING).description(metaCreatedDesc)
    };

    Snippet patchFields = PayloadDocumentation.requestFields(
        SnippetUtils.fieldWithPath("schemas").ignored().type(ARRAY).description(schemasDescription),
        SnippetUtils.fieldWithPath("id").ignored().type(STRING).description(userIdDescription),
        SnippetUtils.fieldWithPath("userName").required().type(STRING).description(usernameDescription),
        SnippetUtils.fieldWithPath("name").required().type(OBJECT).description(nameObjectDescription),
        SnippetUtils.fieldWithPath("name.familyName").required().type(STRING).description(lastnameDescription),
        SnippetUtils.fieldWithPath("name.givenName").required().type(STRING).description(firstnameDescription),
        SnippetUtils.fieldWithPath("phoneNumbers").optional(null).type(ARRAY).description(phoneNumbersListDescription),
        SnippetUtils.fieldWithPath("phoneNumbers[].value").optional(null).type(STRING).description(phoneNumbersDescription),
        SnippetUtils.fieldWithPath("emails").required().type(ARRAY).description(emailListDescription),
        SnippetUtils.fieldWithPath("emails[].value").required().type(STRING).description(emailDescription),
        SnippetUtils.fieldWithPath("emails[].primary").required().type(BOOLEAN).description(emailPrimaryDescription),
        SnippetUtils.fieldWithPath("groups").ignored().type(ARRAY).description("Groups are not created at this time."),
        SnippetUtils.fieldWithPath("approvals").ignored().type(ARRAY).description("Approvals are not created at this time"),
        SnippetUtils.fieldWithPath("active").optional(true).type(BOOLEAN).description(userActiveDescription),
        SnippetUtils.fieldWithPath("verified").optional(false).type(BOOLEAN).description(userVerifiedDescription),
        SnippetUtils.fieldWithPath("origin").optional(OriginKeys.UAA).type(STRING).description(userOriginDescription),
        SnippetUtils.fieldWithPath("zoneId").ignored().type(STRING).description(userZoneIdDescription),
        SnippetUtils.fieldWithPath("passwordLastModified").ignored().type(STRING).description(passwordLastModifiedDescription),
        SnippetUtils.fieldWithPath("externalId").optional(null).type(STRING).description(externalIdDescription),
        SnippetUtils.fieldWithPath("meta.*").ignored().type(OBJECT).description("SCIM object meta data not read."),
        SnippetUtils.fieldWithPath("meta.attributes").optional(null).type(ARRAY).description(metaAttributesDesc)
    );

    private final String scimFilterDescription = "SCIM filter for searching";
    private final String scimAttributeDescription = "Comma separated list of attribute names to be returned.";
    private final String sortByDescription = "Sorting field name, like email or id";
    private final String sortOrderDescription = "Sort order, ascending/descending";
    private final String countDescription = "Max number of results to be returned";

    ParameterDescriptor[] searchUsersParameters = {
        SnippetUtils.parameterWithName("filter").optional(null).description(scimFilterDescription).attributes(key("type").value(STRING)),
        SnippetUtils.parameterWithName("sortBy").optional("created").description(sortByDescription).attributes(key("type").value(STRING)),
        SnippetUtils.parameterWithName("sortOrder").optional("ascending").description(sortOrderDescription).attributes(key("type").value(STRING)),
        SnippetUtils.parameterWithName("startIndex").optional("1").description(startIndexDescription).attributes(key("type").value(NUMBER)),
        SnippetUtils.parameterWithName("count").optional("100").description(countDescription).attributes(key("type").value(NUMBER))
    };

    ParameterDescriptor[] searchWithAttributes = ArrayUtils.addAll(
        searchUsersParameters,
        new ParameterDescriptor[] {SnippetUtils.parameterWithName("attributes").optional(null).description(scimAttributeDescription).attributes(key("type").value(STRING))}
    );

    FieldDescriptor[] searchWithAttributesResponseFields = {
        SnippetUtils.fieldWithPath("startIndex").type(NUMBER).description(startIndexDescription),
        SnippetUtils.fieldWithPath("itemsPerPage").type(NUMBER).description(countAndItemsPerPageDescription),
        SnippetUtils.fieldWithPath("totalResults").type(NUMBER).description(totalResultsDescription),
        SnippetUtils.fieldWithPath("schemas").type(ARRAY).description(schemasDescription),
        SnippetUtils.fieldWithPath("resources").type(ARRAY).description(resourceDescription),
        SnippetUtils.fieldWithPath("resources[].id").type(STRING).description(userIdDescription),
        SnippetUtils.fieldWithPath("resources[].userName").type(STRING).description(usernameDescription),
        SnippetUtils.fieldWithPath("resources[].emails").type(ARRAY).description(emailListDescription),
        SnippetUtils.fieldWithPath("resources[].emails[].value").type(STRING).description(emailDescription),
        SnippetUtils.fieldWithPath("resources[].emails[].primary").type(BOOLEAN).description(emailPrimaryDescription),
        SnippetUtils.fieldWithPath("resources[].active").type(BOOLEAN).description(userActiveDescription),
    };


    private static final HeaderDescriptor IDENTITY_ZONE_ID_HEADER = headerWithName(IdentityZoneSwitchingFilter.HEADER).description("May include this header to administer another zone if using `zones.<zone id>.admin` or `uaa.admin` scope against the default UAA zone.").optional();
    private static final HeaderDescriptor IDENTITY_ZONE_SUBDOMAIN_HEADER = headerWithName(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER).optional().description("If using a `zones.<zoneId>.admin scope/token, indicates what zone this request goes to by supplying a subdomain.");

    private String scimReadToken;
    private String scimWriteToken;
    ScimUser user;
    ScimUserProvisioning userProvisioning;

    @Before
    public void setUp() throws Exception {
        userProvisioning = getWebApplicationContext().getBean(ScimUserProvisioning.class);

        scimReadToken = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(
            getMockMvc(),
            "admin",
            "adminsecret",
            "scim.read",
            null,
            true
        );
        scimWriteToken = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(
            getMockMvc(),
            "admin",
            "adminsecret",
            "scim.write",
            null,
            true
        );

        user = createScimUserObject();
        user = MockMvcUtils.utils().createUser(getMockMvc(), scimWriteToken, user);
        ApprovalStore approvalStore = getWebApplicationContext().getBean(ApprovalStore.class);
        approvalStore.addApproval(
            new Approval()
                .setClientId("client id")
                .setUserId(user.getId())
                .setExpiresAt(new Date(System.currentTimeMillis() + 10000))
                .setScope("scim.read")
                .setStatus(Approval.ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId()
        );
    }

    protected ScimUser createScimUserObject() {
        String username = new RandomValueStringGenerator().generate() + "@test.org";
        ScimUser user = new ScimUser(null, username, "given name", "family name");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        user.setExternalId("test-user");
        user.addPhoneNumber("5555555555");
        return user;
    }

    @Test
    public void test_Find_Users() throws Exception {
        Snippet responseFields = responseFields(searchResponseFields);
        Snippet requestParameters = requestParameters(searchUsersParameters);

        getWebApplicationContext().getBean(UaaUserDatabase.class).updateLastLogonTime(user.getId());
        getWebApplicationContext().getBean(UaaUserDatabase.class).updateLastLogonTime(user.getId());

        getMockMvc().perform(
            get("/Users")
                .accept(APPLICATION_JSON)
                .header("Authorization", "Bearer " + scimReadToken)
                .param("filter", String.format("id eq \"%s\" or email eq \"%s\"", user.getId(), user.getUserName()))
                .param("sortBy", "email")
                .param("count", "50")
                .param("sortOrder", "ascending")
                .param("startIndex", "1")
        )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.resources[0].previousLogonTime").exists())
            .andExpect(jsonPath("$.resources[0].lastLogonTime").exists())
            .andDo(
                document("{ClassName}/{methodName}",
                    preprocessRequest(prettyPrint()),
                    preprocessResponse(prettyPrint()),
                    requestHeaders(
                        headerWithName("Authorization").description("Access token with scim.read or uaa.admin required"),
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                    ),
                    requestParameters,
                    responseFields
                )
            );
    }

    @Test
    public void test_Find_With_Attributes_Users() throws Exception {
        Snippet responseFields = responseFields(searchWithAttributesResponseFields);
        Snippet requestParameters = requestParameters(searchWithAttributes);

        getMockMvc().perform(
            get("/Users")
                .accept(APPLICATION_JSON)
                .header("Authorization", "Bearer " + scimReadToken)
                .param("attributes", "id,userName,emails,active")
                .param("filter", String.format("id eq \"%s\"", user.getId()))
                .param("sortBy", "email")
                .param("count", "50")
                .param("sortOrder", "ascending")
                .param("startIndex", "1")
        )
            .andExpect(status().isOk())
            .andDo(print())
            .andDo(
                document("{ClassName}/{methodName}",
                         preprocessRequest(prettyPrint()),
                         preprocessResponse(prettyPrint()),
                         requestHeaders(
                             headerWithName("Authorization").description("Access token with scim.read or uaa.admin required"),
                             IDENTITY_ZONE_ID_HEADER,
                             IDENTITY_ZONE_SUBDOMAIN_HEADER
                         ),
                         requestParameters,
                         responseFields
                )
            );
    }

    @Test
    public void test_Create_User() throws Exception {

        user = createScimUserObject();

        getMockMvc().perform(
            RestDocumentationRequestBuilders.post("/Users")
                .accept(APPLICATION_JSON)
                .header("Authorization", "Bearer " + scimWriteToken)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.writeValueAsString(user))
        )
            .andExpect(status().isCreated())
            .andDo(
                document("{ClassName}/{methodName}",
                    preprocessRequest(prettyPrint()),
                    preprocessResponse(prettyPrint()),
                    requestHeaders(
                        headerWithName("Authorization").description("Access token with scim.write or uaa.admin required"),
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                    ),
                    createFields,
                    responseFields(createResponse)
                )
            );
    }

    @Test
    public void test_status_unlock_user() throws Exception {
        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setLocked(false);
        String jsonStatus = JsonUtils.writeValueAsString(alteredAccountStatus);

        getMockMvc()
            .perform(
                RestDocumentationRequestBuilders.patch("/Users/{userId}/status", user.getId())
                    .header("Authorization", "Bearer " + scimWriteToken)
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON)
                    .content(jsonStatus)
            )
            .andExpect(status().isOk())
            .andExpect(content().json(jsonStatus))
            .andDo(
                document("{ClassName}/{methodName}",
                    preprocessRequest(prettyPrint()),
                    preprocessResponse(prettyPrint()),
                    RequestDocumentation.pathParameters(SnippetUtils.parameterWithName("userId").description(userIdDescription)),
                    requestHeaders(
                        headerWithName("Authorization").description("Access token with scim.write, uaa.account_status.write, or uaa.admin required"),
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                    ),
                    PayloadDocumentation.requestFields(SnippetUtils.fieldWithPath("locked").optional(null).description("Set to `false` in order to unlock the user when they have been locked out according to the password lock-out policy. Setting to `true` will produce an error, as the user cannot be locked out via the API.").type(BOOLEAN)),
                    PayloadDocumentation.responseFields(SnippetUtils.fieldWithPath("locked").description("The `locked` value given in the request.").type(BOOLEAN))
                )
            );
    }

    @Test
    public void test_status_password_expire_user() throws Exception {
        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setPasswordChangeRequired(true);
        String jsonStatus = JsonUtils.writeValueAsString(alteredAccountStatus);

        getMockMvc()
            .perform(
                RestDocumentationRequestBuilders.patch("/Users/{userId}/status", user.getId())
                    .header("Authorization", "Bearer " + scimWriteToken)
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON)
                    .content(jsonStatus)
            )
            .andExpect(status().isOk())
            .andExpect(content().json(jsonStatus))
            .andDo(
                document("{ClassName}/{methodName}",
                    preprocessRequest(prettyPrint()),
                    preprocessResponse(prettyPrint()),
                    RequestDocumentation.pathParameters(SnippetUtils.parameterWithName("userId").description(userIdDescription)),
                    requestHeaders(
                        headerWithName("Authorization").description("Access token with scim.write, uaa.account_status.write, or uaa.admin required"),
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                    ),
                    PayloadDocumentation.requestFields(SnippetUtils.fieldWithPath("passwordChangeRequired").optional(null).description("Set to `true` in order to force internal user’s password to expire").type(BOOLEAN)),
                    PayloadDocumentation.responseFields(SnippetUtils.fieldWithPath("passwordChangeRequired").description("The `passwordChangeRequired` value given in the request.").type(BOOLEAN))
                )
            );
    }

    @Test
    public void test_Update_User() throws Exception {
        ApprovalStore store = getWebApplicationContext().getBean(ApprovalStore.class);
        Approval approval = new Approval()
            .setUserId(user.getId())
            .setStatus(Approval.ApprovalStatus.DENIED)
            .setScope("uaa.user")
            .setClientId("identity")
            .setExpiresAt(new Date(System.currentTimeMillis() + 30000))
            .setLastUpdatedAt(new Date(System.currentTimeMillis() + 30000));
        store.addApproval(approval, IdentityZoneHolder.get().getId());
        user.setGroups(Collections.emptyList());

        getMockMvc().perform(
            RestDocumentationRequestBuilders.put("/Users/{userId}", user.getId())
                .accept(APPLICATION_JSON)
                .header("Authorization", "Bearer " + scimWriteToken)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header("If-Match", user.getVersion())
                .content(JsonUtils.writeValueAsString(user))
        )
            .andExpect(status().isOk())
            .andDo(
                document("{ClassName}/{methodName}",
                    preprocessRequest(prettyPrint()),
                    preprocessResponse(prettyPrint()),
                    RequestDocumentation.pathParameters(SnippetUtils.parameterWithName("userId").description(userIdDescription)),
                    requestHeaders(
                        headerWithName("Authorization").description("Access token with scim.write or uaa.admin required"),
                        headerWithName("If-Match").description("The version of the SCIM object to be updated. Wildcard (*) accepted."),
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                    ),
                    updateFields,
                    responseFields(updateResponse)
                )
            );
    }

    @Test
    public void test_Patch_User() throws Exception {
        ApprovalStore store = getWebApplicationContext().getBean(ApprovalStore.class);
        Approval approval = new Approval()
            .setUserId(user.getId())
            .setStatus(Approval.ApprovalStatus.DENIED)
            .setScope("uaa.user")
            .setClientId("identity")
            .setExpiresAt(new Date(System.currentTimeMillis() + 30000))
            .setLastUpdatedAt(new Date(System.currentTimeMillis() + 30000));
        store.addApproval(approval, IdentityZoneHolder.get().getId());
        user.setGroups(Collections.emptyList());

        getMockMvc().perform(
            RestDocumentationRequestBuilders.patch("/Users/{userId}", user.getId())
                .accept(APPLICATION_JSON)
                .header("Authorization", "Bearer " + scimWriteToken)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header("If-Match", user.getVersion())
                .content(JsonUtils.writeValueAsString(user))
        )
            .andExpect(status().isOk())
            .andDo(
                document("{ClassName}/{methodName}",
                    preprocessRequest(prettyPrint()),
                    preprocessResponse(prettyPrint()),
                    RequestDocumentation.pathParameters(SnippetUtils.parameterWithName("userId").description(userIdDescription)),
                    requestHeaders(
                        headerWithName("Authorization").description("Access token with scim.write or uaa.admin required"),
                        headerWithName("If-Match").description("The version of the SCIM object to be updated. Wildabccard (*) accepted.")
                    ),
                    patchFields,
                    responseFields(updateResponse)
                )
            );
    }

    @Test
    public void test_Delete_User() throws Exception {
        ApprovalStore store = getWebApplicationContext().getBean(ApprovalStore.class);
        Approval approval = new Approval()
            .setUserId(user.getId())
            .setStatus(Approval.ApprovalStatus.APPROVED)
            .setScope("uaa.user")
            .setClientId("identity")
            .setExpiresAt(new Date(System.currentTimeMillis() + 30000))
            .setLastUpdatedAt(new Date(System.currentTimeMillis() + 30000));
        store.addApproval(approval, IdentityZoneHolder.get().getId());

        getMockMvc().perform(
            RestDocumentationRequestBuilders.delete("/Users/{userId}", user.getId())
                .accept(APPLICATION_JSON)
                .header("Authorization", "Bearer " + scimWriteToken)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header("If-Match", user.getVersion())
        )
            .andExpect(status().isOk())
            .andDo(
                document("{ClassName}/{methodName}",
                    preprocessRequest(prettyPrint()),
                    preprocessResponse(prettyPrint()),
                    RequestDocumentation.pathParameters(SnippetUtils.parameterWithName("userId").description(userIdDescription)),
                    requestHeaders(
                        headerWithName("Authorization").description("Access token with scim.write or uaa.admin required"),
                        headerWithName("If-Match").optional().description("The version of the SCIM object to be deleted. Optional."),
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                    ),

                    responseFields(updateResponse)
                )
            );
    }

    @Test
    public void test_Get_User() throws Exception {
        ApprovalStore store = getWebApplicationContext().getBean(ApprovalStore.class);
        Approval approval = new Approval()
            .setUserId(user.getId())
            .setStatus(Approval.ApprovalStatus.APPROVED)
            .setScope("uaa.user")
            .setClientId("identity")
            .setExpiresAt(new Date(System.currentTimeMillis() + 30000))
            .setLastUpdatedAt(new Date(System.currentTimeMillis() + 30000));
        store.addApproval(approval, IdentityZoneHolder.get().getId());

        getWebApplicationContext().getBean(UaaUserDatabase.class).updateLastLogonTime(user.getId());
        getWebApplicationContext().getBean(UaaUserDatabase.class).updateLastLogonTime(user.getId());

        getMockMvc().perform(
            RestDocumentationRequestBuilders.get("/Users/{userId}", user.getId())
                .accept(APPLICATION_JSON)
                .header("Authorization", "Bearer " + scimReadToken)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header("If-Match", user.getVersion())
        )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.previousLogonTime").exists())
            .andExpect(jsonPath("$.lastLogonTime").exists())
            .andDo(
                document("{ClassName}/{methodName}",
                    preprocessRequest(prettyPrint()),
                    preprocessResponse(prettyPrint()),
                    RequestDocumentation.pathParameters(SnippetUtils.parameterWithName("userId").description(userIdDescription)),
                    requestHeaders(
                        headerWithName("Authorization").description("Access token with scim.write or uaa.admin required"),
                        headerWithName("If-Match").optional().description("The version of the SCIM object to be deleted. Optional."),
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                    ),

                    responseFields(updateResponse)
                )
            );
    }


    @Test
    public void test_Change_Password() throws Exception {
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword("secret");
        request.setPassword("newsecret");

        String myToken = MockMvcUtils.utils().getUserOAuthAccessToken(getMockMvc(), "app", "appclientsecret", user.getUserName(), "secret", null, null, true);

        getMockMvc().perform(
            RestDocumentationRequestBuilders.put("/Users/{userId}/password", user.getId())
                .accept(APPLICATION_JSON)
                .header("Authorization", "Bearer " + myToken)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header("If-Match", user.getVersion())
                .content(JsonUtils.writeValueAsString(request))
        )
            .andExpect(status().isOk())
            .andDo(
                document("{ClassName}/{methodName}",
                    preprocessRequest(prettyPrint()),
                    preprocessResponse(prettyPrint()),
                    RequestDocumentation.pathParameters(SnippetUtils.parameterWithName("userId").description(userIdDescription)),
                    requestHeaders(
                        headerWithName("Authorization").description("Access token with password.write or uaa.admin required"),
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                    ),
                    PayloadDocumentation.requestFields(
                        SnippetUtils.fieldWithPath("oldPassword").required().description("Old password. Optional when resetting another users password as an admin with uaa.admin scope").type(STRING),
                        SnippetUtils.fieldWithPath("password").required().description("New password.").type(STRING)
                    ),
                    PayloadDocumentation.responseFields(
                        SnippetUtils.fieldWithPath("status").description("Will be 'ok' if password changed successfully."),
                        SnippetUtils.fieldWithPath("message").description("Will be 'password updated' if password changed successfully.")
                    )
                )
            );
    }

    @Test
    public void getUserVerificationLink() throws Exception {
        String accessToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "uaa.admin");

        String email = "joel" + new RandomValueStringGenerator().generate() + "@example.com";
        ScimUser joel = new ScimUser(null, email, "Joel", "D'sa");
        joel.setVerified(false);
        joel.addEmail(email);
        joel = userProvisioning.createUser(joel, "pas5Word", IdentityZoneHolder.get().getId());

        MockHttpServletRequestBuilder get = RestDocumentationRequestBuilders.get("/Users/{userId}/verify-link", joel.getId())
            .header("Authorization", "Bearer " + accessToken)
            .param("redirect_uri", "http://redirect.to/app")
            .accept(APPLICATION_JSON);

        Snippet requestHeaders = requestHeaders(headerWithName("Authorization").description("The bearer token, with a pre-amble of `Bearer`"), IDENTITY_ZONE_ID_HEADER, IDENTITY_ZONE_SUBDOMAIN_HEADER);
        Snippet requestParameters = RequestDocumentation.requestParameters(SnippetUtils.parameterWithName("redirect_uri").required().description("Location where the user will be redirected after verifying by clicking the verification link").attributes(key("type").value(STRING)));
        Snippet responseFields = PayloadDocumentation.responseFields(SnippetUtils.fieldWithPath("verify_link").description("Location the user must visit and authenticate to verify"));

        Snippet pathParameters = pathParameters(
            RequestDocumentation.parameterWithName("userId").description("The ID of the user to verify")
        );
        getMockMvc().perform(get)
            .andDo(print())
            .andExpect(status().isOk())
            .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()),
                pathParameters, requestHeaders, requestParameters, responseFields))
        ;
    }

    @Test
    public void directlyVerifyUser() throws Exception {
        String accessToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "uaa.admin");

        String email = "billy_o@example.com";
        ScimUser billy = new ScimUser(null, email, "William", "d'Orange");
        billy.setVerified(false);
        billy.addEmail(email);
        billy.setVersion(12);
        billy = userProvisioning.createUser(billy, "pas5Word", IdentityZoneHolder.get().getId());

        Snippet requestHeaders = requestHeaders(headerWithName("Authorization").description("The bearer token, with a pre-amble of `Bearer`"),
            headerWithName("If-Match").description("(Optional) The expected current version of the user, which will prevent update if the version does not match"),
            IDENTITY_ZONE_ID_HEADER,
            IDENTITY_ZONE_SUBDOMAIN_HEADER);

        Snippet pathParameters = pathParameters(
            RequestDocumentation.parameterWithName("userId").description("The ID of the user to verify")
        );

        MockHttpServletRequestBuilder get = RestDocumentationRequestBuilders.get("/Users/{userId}/verify", billy.getId())
            .header("Authorization", "Bearer " + accessToken)
            .header("If-Match", "12")
            .accept(APPLICATION_JSON);

        getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()),
                pathParameters, requestHeaders))
        ;
    }

}
