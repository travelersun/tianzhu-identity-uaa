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

import com.fasterxml.jackson.core.type.TypeReference;
import com.tianzhu.identity.uaa.test.SnippetUtils;
import org.apache.commons.lang3.ArrayUtils;
import com.tianzhu.identity.uaa.mock.InjectedMockContextTest;
import com.tianzhu.identity.uaa.mock.util.MockMvcUtils;
import com.tianzhu.identity.uaa.scim.ScimGroup;
import com.tianzhu.identity.uaa.scim.ScimGroupMember;
import com.tianzhu.identity.uaa.scim.ScimUser;
import com.tianzhu.identity.uaa.util.JsonUtils;
import com.tianzhu.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.Before;
import org.junit.Test;
import org.springframework.restdocs.headers.HeaderDescriptor;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.payload.PayloadDocumentation;
import org.springframework.restdocs.request.RequestDocumentation;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static java.util.Arrays.asList;
import static com.tianzhu.identity.uaa.scim.ScimGroupMember.Type.USER;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.delete;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.patch;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.put;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessRequest;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.ARRAY;
import static org.springframework.restdocs.payload.JsonFieldType.BOOLEAN;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ScimGroupEndpointsDocs extends InjectedMockContextTest {

    private final RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private final FieldDescriptor displayNameRequestField = SnippetUtils.fieldWithPath("displayName").required().description("An identifier, unique within the identity zone");
    private final FieldDescriptor descriptionRequestField = SnippetUtils.fieldWithPath("description").optional(null).type(STRING).description("Human readable description of the group, displayed e.g. when approving scopes");
    private final FieldDescriptor membersRequestField = SnippetUtils.fieldWithPath("members").optional(null).type(ARRAY).description("Members to be included in the group");
    private final FieldDescriptor memberValueRequestField = SnippetUtils.fieldWithPath("members[].value").constrained("Required for each item in `members`").type(STRING).description("The globally-unique ID of the member entity, either a user ID or another group ID");
    private final FieldDescriptor memberTypeRequestField = SnippetUtils.fieldWithPath("members[].type").optional(USER).type(STRING).description("Either `\"USER\"` or `\"GROUP\"`");
    private final FieldDescriptor memberOriginRequestField = SnippetUtils.fieldWithPath("members[].origin").optional("uaa").type(STRING).description("The alias of the identity provider that authenticated this user. `\"uaa\"` is an internal UAA user. This value will NOT change during an update (put request) if the membership already exists under a different origin.");
    private final FieldDescriptor memberOperationRequestField = SnippetUtils.fieldWithPath("members[].operation").optional(null).type(STRING).description("\"delete\" if the corresponding member shall be deleted");
    private final FieldDescriptor metaAttributesRequestField = SnippetUtils.fieldWithPath("meta.attributes").optional(null).type(ARRAY).description("Names of attributes that shall be deleted");
    private String scimReadToken;
    private String scimWriteToken;

    private static final HeaderDescriptor IDENTITY_ZONE_ID_HEADER = headerWithName(IdentityZoneSwitchingFilter.HEADER).description("May include this header to administer another zone if using `zones.<zone id>.admin` or `uaa.admin` scope against the default UAA zone.").optional();
    private static final HeaderDescriptor IDENTITY_ZONE_SUBDOMAIN_HEADER = headerWithName(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER).optional().description("If using a `zones.<zoneId>.admin scope/token, indicates what zone this request goes to by supplying a subdomain.");

    FieldDescriptor[] responseFieldDescriptors = {
        SnippetUtils.fieldWithPath("id").description("The globally unique group ID"),
        SnippetUtils.fieldWithPath("displayName").description("The identifier specified upon creation of the group, unique within the identity zone"),
        SnippetUtils.fieldWithPath("description").description("Human readable description of the group, displayed e.g. when approving scopes"),
        SnippetUtils.fieldWithPath("members").description("Array of group members"),
        SnippetUtils.fieldWithPath("members[].value").description("Globally unique identifier of the member, either a user ID or another group ID"),
        SnippetUtils.fieldWithPath("members[].type").description("Either `\"USER\"` or `\"GROUP\"`"),
        SnippetUtils.fieldWithPath("members[].origin").description("The alias of the identity provider that authenticated this user. `\"uaa\"` is an internal UAA user."),
        SnippetUtils.fieldWithPath("zoneId").description("Identifier for the identity zone to which the group belongs"),
        SnippetUtils.fieldWithPath("meta.version").description("The version of the group entity"),
        SnippetUtils.fieldWithPath("meta.created").description("The time the group was created"),
        SnippetUtils.fieldWithPath("meta.lastModified").description("The time the group was last updated"),
        SnippetUtils.fieldWithPath("schemas").description("`[ \"urn:scim:schemas:core:1.0\" ]`")
    };

    private final Snippet scimGroupRequestFields = requestFields(
        displayNameRequestField,
        descriptionRequestField,
        membersRequestField,
        memberValueRequestField,
        memberTypeRequestField,
        memberOriginRequestField
    );

    private final Snippet scimGroupPatchRequestFields = requestFields(
            displayNameRequestField,
            descriptionRequestField,
            membersRequestField,
            memberValueRequestField,
            memberTypeRequestField,
            memberOriginRequestField,
            memberOperationRequestField,
            metaAttributesRequestField
        );

    @Before
    public void setUp() throws Exception {
        scimReadToken = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret",
            "scim.read", null, true);

        scimWriteToken = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret",
            "scim.write", null, true);
    }

    @Test
    public void createRetrieveUpdateListScimGroup() throws Exception {
        // Create

        ScimGroup scimGroup = new ScimGroup();
        scimGroup.setDisplayName("Cool Group Name");
        scimGroup.setDescription("the cool group");

        ScimUser memberUser = newScimUser();
        scimGroup.setMembers(Collections.singletonList(new ScimGroupMember(memberUser.getId())));

        Snippet responseFields = responseFields(responseFieldDescriptors);

        ResultActions createResult = createScimGroupHelper(scimGroup)
            .andDo(document("{ClassName}/createScimGroup",
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token with scope `scim.write`"),
                    IDENTITY_ZONE_ID_HEADER,
                    IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                scimGroupRequestFields,
                responseFields));

        scimGroup = JsonUtils.readValue(createResult.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        scimGroup.setDisplayName("Cooler Group Name for Update");


        // Update

        MockHttpServletRequestBuilder put = put("/Groups/{groupId}", scimGroup.getId())
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("If-Match", scimGroup.getVersion())
            .contentType(APPLICATION_JSON)
            .content(serializeWithoutMeta(scimGroup));

        ResultActions updateResult = getMockMvc().perform(put).andExpect(status().isOk())
            .andDo(document("{ClassName}/updateScimGroup",
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                RequestDocumentation.pathParameters(
                    SnippetUtils.parameterWithName("groupId").description("Globally unique identifier of the group to update")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token with scope `scim.write` or `groups.update`"),
                    headerWithName("If-Match").description("The version of the SCIM object to be updated. Wildcard (*) accepted."),
                    IDENTITY_ZONE_ID_HEADER,
                    IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                scimGroupRequestFields,
                responseFields));

        // Patch
        MockHttpServletRequestBuilder patch = patch("/Groups/{groupId}", scimGroup.getId())
                .header("Authorization", "Bearer " + scimWriteToken)
                .header("If-Match", "*")
                .contentType(APPLICATION_JSON)
                .content(serializeWithoutMeta(scimGroup));

            ResultActions patchResult = getMockMvc().perform(patch).andExpect(status().isOk())
                .andDo(document("{ClassName}/patchScimGroup",
                    preprocessRequest(prettyPrint()),
                    preprocessResponse(prettyPrint()),
                    RequestDocumentation.pathParameters(
                        SnippetUtils.parameterWithName("groupId").description("Globally unique identifier of the group to update")
                    ),
                    requestHeaders(
                        headerWithName("Authorization").description("Bearer token with scope `scim.write` or `groups.update`"),
                        headerWithName("If-Match").description("The version of the SCIM object to be updated. Wildcard (*) accepted.")
                    ),
                    scimGroupPatchRequestFields,
                    responseFields));

        // Retrieve

        scimGroup = JsonUtils.readValue(updateResult.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        MockHttpServletRequestBuilder get = get("/Groups/{groupId}", scimGroup.getId())
            .header("Authorization", "Bearer " + scimReadToken);

        ResultActions retrieveResult = getMockMvc().perform(get).andExpect(status().isOk())
            .andDo(document("{ClassName}/retrieveScimGroup",
                preprocessResponse(prettyPrint()),
                RequestDocumentation.pathParameters(
                    SnippetUtils.parameterWithName("groupId").description("Globally unique identifier of the group to retrieve")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token with scope `scim.read`"),
                    IDENTITY_ZONE_ID_HEADER,
                    IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                responseFields));


        // List

        scimGroup = JsonUtils.readValue(retrieveResult.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        Snippet requestParameters = RequestDocumentation.requestParameters(
            SnippetUtils.parameterWithName("filter").optional("id pr").type(STRING).description("A SCIM filter over groups"),
            SnippetUtils.parameterWithName("sortBy").optional("created").type(STRING).description("The field of the SCIM group to sort by"),
            SnippetUtils.parameterWithName("sortOrder").optional("ascending").type(NUMBER).description("Sort in `ascending` or `descending` order"),
            SnippetUtils.parameterWithName("startIndex").optional("1").type(NUMBER).description("The index of the first result of this page within all matches"),
            SnippetUtils.parameterWithName("count").optional("100").type(NUMBER).description("Maximum number of results to return in a single page")
        );

        MockHttpServletRequestBuilder getList = get("/Groups")
            .header("Authorization", "Bearer " + scimReadToken)
            .param("filter", String.format("id eq \"%s\" or displayName eq \"%s\"", scimGroup.getId(), scimGroup.getDisplayName()))
            .param("sortBy", "lastModified")
            .param("count", "50")
            .param("sortOrder", "descending")
            .param("startIndex", "1");

        List<FieldDescriptor> fields = new ArrayList<>(asList(SnippetUtils.subFields("resources[]", responseFieldDescriptors)));
        fields.addAll(asList(
            SnippetUtils.fieldWithPath("itemsPerPage").description("The page-size used to produce the current page of results"),
            SnippetUtils.fieldWithPath("startIndex").description("The index of the first result of this page within all matches"),
            SnippetUtils.fieldWithPath("totalResults").description("The number of groups that matched the given filter"),
            SnippetUtils.fieldWithPath("schemas").description("`[ \"urn:scim:schemas:core:1.0\" ]`")
        ));
        Snippet listGroupResponseFields = responseFields(fields.toArray(new FieldDescriptor[fields.size()]));

        getMockMvc().perform(getList).andExpect(status().isOk())
            .andDo(document("{ClassName}/listScimGroups",
                preprocessResponse(prettyPrint()),
                requestParameters,
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token with scope `scim.read`"),
                    headerWithName(IdentityZoneSwitchingFilter.HEADER).optional().description("If using a `zones.<zoneId>.admin scope/token, indicates what zone this request goes to by supplying a zone_id."),
                    IDENTITY_ZONE_ID_HEADER,
                    IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                listGroupResponseFields));

        // Check Membership

        FieldDescriptor[] idempotentMembershipFields = {
            SnippetUtils.fieldWithPath("value").required().description("The globally unique identifier the user or group which is a member of the specified by `groupId`"),
            SnippetUtils.fieldWithPath("type").required().description("Either `\"USER\"` or `\"GROUP\"`, indicating what type of entity the group membership refers to, and whether `value` denotes a user ID or group ID"),
            SnippetUtils.fieldWithPath("origin").required().description("The originating IDP of the entity, or `\"uaa\"` for groups and internal users")
        };

        MockHttpServletRequestBuilder getMember = get("/Groups/{groupId}/members/{memberId}", scimGroup.getId(), memberUser.getId())
            .header("Authorization", "Bearer " + scimReadToken);

        getMockMvc().perform(getMember).andExpect(status().isOk())
            .andDo(document("{ClassName}/getMemberOfGroup",
                preprocessResponse(prettyPrint()),
            RequestDocumentation.pathParameters(
                    SnippetUtils.parameterWithName("groupId").description("The globally unique identifier of the group"),
                    SnippetUtils.parameterWithName("memberId").description("The globally unique identifier the user or group which is a member of the specified by `groupId`")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token with scope `scim.read`"),
                    IDENTITY_ZONE_ID_HEADER,
                    IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                responseFields(
                    idempotentMembershipFields
                )
            ));

        // Remove Member

        MockHttpServletRequestBuilder removeMember = delete("/Groups/{groupId}/members/{memberId}", scimGroup.getId(), memberUser.getId())
                .header("Authorization", "Bearer " + scimWriteToken);

        getMockMvc().perform(removeMember).andExpect(status().isOk())
            .andDo(document("{ClassName}/removeMemberFromGroup",
                preprocessResponse(prettyPrint()),
                RequestDocumentation.pathParameters(
                    SnippetUtils.parameterWithName("groupId").description("The globally unique identifier of the group"),
                    SnippetUtils.parameterWithName("memberId").description("The globally unique identifier of the entity, i.e. the user or group, to be removed from membership in the group specified by `groupId`")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token with scope `scim.write`"),
                    IDENTITY_ZONE_ID_HEADER,
                    IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                PayloadDocumentation.responseFields(
                    SnippetUtils.fieldWithPath("origin").description("The originating IDP of the entity"),
                    SnippetUtils.fieldWithPath("type").description("Either `\"USER\"` or `\"GROUP\"`, indicating what type of entity the group membership refers to"),
                    SnippetUtils.fieldWithPath("value").description("The globally unique identifier of the user or group which has been removed from the group specified by `groupId`")
                )
            ));

        // Add Member

        ScimGroupMember<ScimUser> groupMember = new ScimGroupMember<>(memberUser);
        groupMember.setEntity(null); // We don't need to include the serialized user in the request
        MockHttpServletRequestBuilder addMember = post("/Groups/{groupId}/members", scimGroup.getId())
            .header("Authorization", "Bearer " + scimWriteToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(groupMember));

        getMockMvc().perform(addMember).andExpect(status().isCreated())
            .andDo(document("{ClassName}/addMemberToGroup",
            preprocessResponse(prettyPrint()),
                RequestDocumentation.pathParameters(
                    SnippetUtils.parameterWithName("groupId").description("The globally unique identifier of the group")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token with scope `scim.write`"),
                    IDENTITY_ZONE_ID_HEADER,
                    IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                requestFields(
                    idempotentMembershipFields
                ),
                responseFields(
                    idempotentMembershipFields
                )
            ));

        // List Members

        MockHttpServletRequestBuilder listMembers = get("/Groups/{groupId}/members", scimGroup.getId())
                .param("returnEntities", "true")
                .header("Authorization", "Bearer " + scimReadToken);

        getMockMvc().perform(listMembers).andExpect(status().isOk())
            .andDo(print())
            .andDo(document("{ClassName}/listMembersOfGroup",
                preprocessResponse(prettyPrint()),
                RequestDocumentation.pathParameters(
                    SnippetUtils.parameterWithName("groupId").required().description("The globally unique identifier of the group")
                ),
                RequestDocumentation.requestParameters(
                    SnippetUtils.parameterWithName("returnEntities").type(BOOLEAN).optional("false").description("Set to `true` to return the SCIM entities which have membership in the group")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token with scope `scim.read`"),
                    IDENTITY_ZONE_ID_HEADER,
                    IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                PayloadDocumentation.responseFields(
                    SnippetUtils.subFields("[]",
                              ArrayUtils.addAll(
                                  idempotentMembershipFields,
                                  SnippetUtils.fieldWithPath("entity.*").description("Present only if requested with `returnEntities`; user or group details for each entity that is a member of this group"),
                                  SnippetUtils.fieldWithPath("entity.meta.*").ignored(), //users are documented in the user section
                                  SnippetUtils.fieldWithPath("entity.name.*").ignored(),
                                  SnippetUtils.fieldWithPath("entity.emails[].*").ignored(),
                                  SnippetUtils.fieldWithPath("entity.schemas").ignored()
                              )
                    )
                )
            ));

        // Delete

        MockHttpServletRequestBuilder delete = delete("/Groups/{groupId}", scimGroup.getId())
                .header("Authorization", "Bearer " + scimWriteToken);

        getMockMvc().perform(delete).andExpect(status().isOk())
            .andDo(document("{ClassName}/deleteScimGroup",
                preprocessResponse(prettyPrint()),
                RequestDocumentation.pathParameters(
                    SnippetUtils.parameterWithName("groupId").description("The globally unique identifier of the group")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token with scope `scim.write`"),
                    headerWithName("If-Match").description("The version of the SCIM object to be updated. Wildcard (*) accepted.").attributes(key("constraints").value("Optional (defaults to `*`)")).optional(),
                    IDENTITY_ZONE_ID_HEADER,
                    IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                responseFields));

    }

    private static String serializeWithoutMeta(ScimGroup scimGroup) {
        Map<String, Object> content = JsonUtils.readValue(JsonUtils.writeValueAsString(scimGroup), new TypeReference<Map<String, Object>>() {
        });
        content.remove("id");
        content.remove("zoneId");
        content.remove("meta");
        content.remove("schemas");
        return JsonUtils.writeValueAsString(content);
    }

    private ResultActions createScimGroupHelper(ScimGroup scimGroup) throws Exception {
        MockHttpServletRequestBuilder post = post("/Groups")
            .header("Authorization", "Bearer " + scimWriteToken)
            .contentType(APPLICATION_JSON)
            .content(serializeWithoutMeta(scimGroup));

        return getMockMvc().perform(post).andExpect(status().isCreated());
    }

    private ScimUser newScimUser() throws Exception {
        String userName = generator.generate();
        ScimUser member = new ScimUser(null, userName, "cool-name", "cool-familyName");
        member.setPassword("password");
        member.setPrimaryEmail("cool@chill.com");
        member = MockMvcUtils.utils().createUser(getMockMvc(), scimWriteToken, member);
        return member;
    }


}
