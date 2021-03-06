package com.tianzhu.identity.uaa.impl.config;

import com.tianzhu.identity.uaa.authorization.LdapGroupMappingAuthorizationManager;
import com.tianzhu.identity.uaa.provider.ldap.LdapGroupToScopesMapper;
import com.tianzhu.identity.uaa.scim.ScimGroupExternalMembershipManager;
import com.tianzhu.identity.uaa.scim.ScimGroupProvisioning;
import org.springframework.context.annotation.*;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

@Configuration
@Conditional(LdapGroupsMappedToScopesConfig.IfConfigured.class)
@Import(LdapGroupsConfig.class)
public class LdapGroupsMappedToScopesConfig {

  public static class IfConfigured implements Condition {
    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
      String ldapGroupsFile = context.getEnvironment().getProperty("ldap.groups.file");
      return ldapGroupsFile != null && ldapGroupsFile.equals("ldap/ldap-groups-map-to-scopes.xml");
    }
  }

  @Bean
  public String configuredGroupRoleAttribute() {
      return "spring.security.ldap.dn";
  }

  @Bean
  public LdapGroupMappingAuthorizationManager ldapGroupMappingAuthorizationManager(ScimGroupExternalMembershipManager externalMembershipManager, ScimGroupProvisioning provisioning) {
    LdapGroupMappingAuthorizationManager ldapGroupMappingAuthorizationManager = new LdapGroupMappingAuthorizationManager();
    ldapGroupMappingAuthorizationManager.setExternalMembershipManager(externalMembershipManager);
    ldapGroupMappingAuthorizationManager.setScimGroupProvisioning(provisioning);
    return ldapGroupMappingAuthorizationManager;
  }

  @Bean
  public GrantedAuthoritiesMapper ldapAuthoritiesMapper(LdapGroupMappingAuthorizationManager ldapGroupMappingAuthorizationManager) {
    LdapGroupToScopesMapper ldapGroupToScopesMapper = new LdapGroupToScopesMapper();
    ldapGroupToScopesMapper.setGroupMapper(ldapGroupMappingAuthorizationManager);
    return ldapGroupToScopesMapper;
  }

  @Bean
  public String testLdapGroup() {
    return "ldap-groups-map-to-scopes.xml";
  }
}
