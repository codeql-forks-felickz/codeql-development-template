package org.apache.directory.server.core;

import org.apache.directory.server.core.filtering.EntryFilteringCursor;
import org.apache.directory.shared.ldap.filter.ExprNode;
import org.apache.directory.shared.ldap.filter.SearchScope;
import org.apache.directory.shared.ldap.message.AliasDerefMode;
import org.apache.directory.shared.ldap.name.LdapDN;

public interface CoreSession {
  EntryFilteringCursor search(
      LdapDN dn,
      SearchScope scope,
      ExprNode filter,
      AliasDerefMode aliasDerefMode,
      java.util.Set<Object> returningAttributes)
      throws Exception;
}
